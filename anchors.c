/*
 * anchors.c
 *
 * Copyright (C) 2025, Samo Pogačnik <samo_pogacnik@t-2.net>
 *
 */

#define USE_THE_REPOSITORY_VARIABLE
#define DISABLE_SIGN_COMPARE_WARNINGS

#include "git-compat-util.h"
#include "environment.h"
#include "tag.h"
#include "object-file.h"
#include "object-name.h"
#include "odb.h"
#include "commit.h"
#include "tree.h"
#include "blob.h"
#include "alloc.h"
#include "gpg-interface.h"
#include "hex.h"
#include "packfile.h"
#include "object-file-convert.h"
#include "ident.h"
#include "shallow.h"
#include "refs.h"
#include "oid-array.h"
#include "remote.h"
#include "anchors.h"
#include "trace.h"

struct anchors_update_lists {
	struct string_list refs;
	struct string_list refs_to_keep;
};

static int do_sign(struct strbuf *buffer, struct object_id **compat_oid,
		   struct object_id *compat_oid_buf)
{
	struct repository *r = the_repository;
	const struct git_hash_algo *compat = r->compat_hash_algo;
	struct strbuf sig = STRBUF_INIT, compat_sig = STRBUF_INIT;
	struct strbuf compat_buf = STRBUF_INIT;
	char *keyid = get_signing_key();
	int ret = -1;

	if (!keyid) { /* proceed without signing */
		ret = 0;
		goto out;
	}

	if (sign_buffer(buffer, &sig, keyid))
		goto out;

	if (compat) {
		const struct git_hash_algo *algo = r->hash_algo;

		if (convert_object_file(r ,&compat_buf, algo, compat,
					buffer->buf, buffer->len, OBJ_TAG, 1))
			goto out;
		if (sign_buffer(&compat_buf, &compat_sig, keyid))
			goto out;
		add_header_signature(&compat_buf, &sig, algo);
		strbuf_addbuf(&compat_buf, &compat_sig);
		hash_object_file(compat, compat_buf.buf, compat_buf.len,
				 OBJ_TAG, compat_oid_buf);
		*compat_oid = compat_oid_buf;
	}

	if (compat_sig.len)
		add_header_signature(buffer, &compat_sig, compat);

	strbuf_addbuf(buffer, &sig);
	ret = 0;
out:
	strbuf_release(&sig);
	strbuf_release(&compat_sig);
	strbuf_release(&compat_buf);
	free(keyid);
	return ret;
}

static timestamp_t parse_anchor_tag_date(const char *buf, const char *tail)
{
	const char *dateptr;

	while (buf < tail && *buf++ != '>')
		/* nada */;
	if (buf >= tail)
		return 0;
	dateptr = buf;
	while (buf < tail && *buf++ != '\n')
		/* nada */;
	if (buf >= tail)
		return 0;
	/* dateptr < buf && buf[-1] == '\n', so parsing will stop at buf-1 */
	return parse_timestamp(dateptr, NULL, 10);
}

static int parse_anchor_tag_buffer(struct repository *r, struct tag *item, const void *data, unsigned long size)
{
	struct object_id oid;
	char type[20];
	const char *bufptr = data;
	const char *tail = bufptr + size;
	const char *nl;

	if (item->tag) {
		/*
		 * Presumably left over from a previous failed parse;
		 * clear it out in preparation for re-parsing (we'll probably
		 * hit the same error, which lets us tell our current caller
		 * about the problem).
		 */
		FREE_AND_NULL(item->tag);
	}

	if (size < the_hash_algo->hexsz + 24)
		return -1;
	if (memcmp("object ", bufptr, 7) || parse_oid_hex(bufptr + 7, &oid, &bufptr) || *bufptr++ != '\n')
		return -1;

	if (!starts_with(bufptr, "type "))
		return -1;
	bufptr += 5;
	nl = memchr(bufptr, '\n', tail - bufptr);
	if (!nl || sizeof(type) <= (nl - bufptr))
		return -1;
	memcpy(type, bufptr, nl - bufptr);
	type[nl - bufptr] = '\0';
	bufptr = nl + 1;

	if (!strcmp(type, commit_type)) {
		item->tagged = (struct object *)lookup_commit(r, &oid);
	} else {
		return error("unknown tag type '%s' in %s",
			     type, oid_to_hex(&item->object.oid));
	}

	if (!item->tagged)
		return error("bad tag pointer to %s in %s",
			     oid_to_hex(&oid),
			     oid_to_hex(&item->object.oid));

	if (bufptr + 4 < tail && starts_with(bufptr, "tag "))
		; 		/* good */
	else
		return -1;
	bufptr += 4;
	nl = memchr(bufptr, '\n', tail - bufptr);
	if (!nl)
		return -1;
	item->tag = xmemdupz(bufptr, nl - bufptr);
	bufptr = nl + 1;

	if (bufptr + 7 < tail && starts_with(bufptr, "tagger "))
		item->date = parse_anchor_tag_date(bufptr, tail);
	else
		item->date = 0;

	item->object.parsed = 1;
	return 0;
}

static int verify_boundary_anchor(struct string_list_item *refname)
{
	struct repository *r = the_repository;
	struct object_id anchor_tag_oid;
	struct tag *item;
	int flags;
	enum object_type type;
	char *buf;
	unsigned long size;
	struct signature_check sigc;
	struct strbuf payload = STRBUF_INIT;
	struct strbuf signature = STRBUF_INIT;
	struct strbuf name_check = STRBUF_INIT;
	int ret = 0;

	if (refs_read_ref(get_main_ref_store(r), refname->string, &anchor_tag_oid)) {
		return error("cannot verify: anchor_tag '%s' not found.", refname->string);
	}
	item = lookup_tag(r, &anchor_tag_oid);

	flags = GPG_VERIFY_OMIT_STATUS;
	type = odb_read_object_info(r->objects, &anchor_tag_oid, NULL);
	if (type != OBJ_TAG)
		return error("%s: cannot verify a non-tag object of type %s.",
				repo_find_unique_abbrev(r, &anchor_tag_oid, DEFAULT_ABBREV),
				type_name(type));

	buf = odb_read_object(r->objects, &anchor_tag_oid, &type, &size);
	if (!buf)
		return error("%s: unable to read file.",
				repo_find_unique_abbrev(r, &anchor_tag_oid, DEFAULT_ABBREV));

	memset(&sigc, 0, sizeof(sigc));

	if (parse_signature(buf, size, &payload, &signature)) {
		sigc.payload_type = SIGNATURE_PAYLOAD_TAG;
		sigc.payload = strbuf_detach(&payload, &sigc.payload_len);
		if ((ret = check_signature(&sigc, signature.buf, signature.len)))
			error("Error checking anctor tag object signature");

		if (!(flags & GPG_VERIFY_OMIT_STATUS))
			print_signature_buffer(&sigc, flags);

		signature_check_clear(&sigc);
		strbuf_release(&payload);
		strbuf_release(&signature);
	} else {
		if (flags & GPG_VERIFY_VERBOSE)
			write_in_full(1, buf, size);
		warning("anchor ref: path '%s', anchor tag oid '%s': no signature\n", refname->string, oid_to_hex(&anchor_tag_oid));
	}

	if (!ret)
		if ((ret = parse_anchor_tag_buffer(r, item, buf, size)))
			error("Error in parsing anchor tag object");

	if (!ret) {
		char *dash;
		strbuf_addf(&name_check, "refs/anchors/%s", item->tag + 7);
		if ((dash = index(name_check.buf, '-'))) {
			*dash = '/';
		} else {
			error("Error in anchor tag object: header tag");
			ret = 1;
		}
	}
	if (!ret) {
		if ((ret = strcmp(refname->string, name_check.buf))) {
			error("Error in anchor tag object: header tag");
			ret = 1;
		}
	}

	if (!ret) {
		struct commit *c;
		if (!(c = lookup_commit(r, &item->tagged->oid))) {
			error("Anchored boundary commit object not found: '%s'", oid_to_hex(&item->tagged->oid));
			ret = 1;
		}
	}

	free(buf);
	return ret;
}

/*
 * Verify anchors (anchor tags and references) for a grafted shallow
 * boundary commit (child_oid).
 * Find commit's missing parents and verify anchor tag object and
 * anchor ref for each missing parent.
 */
static void verify_boundary_anchors(const struct object_id *child_oid, struct string_list *refs)
{
	struct repository *r = the_repository;
	struct string_list_item *item;
	struct commit *c;
	struct object *o;

	if (!child_oid)
		die("oops: (%s)", oid_to_hex(child_oid));

	o = parse_object_with_flags(r, child_oid,
						   PARSE_OBJECT_SKIP_HASH_CHECK |
						   PARSE_OBJECT_DISCARD_TREE);
	if (!o)
		die("oops: failed to get object (%s)", oid_to_hex(child_oid));

	unregister_shallow(&o->oid);
	o->parsed = 0;
	parse_commit_or_die((struct commit *)o);
	c = ((struct commit *)o);

	struct commit_list *p;
	for (p = c->parents; p; p = p->next) {
		int anchor_missing = 1;
		for_each_string_list_item(item, refs) {
			struct strbuf sb = STRBUF_INIT;
			strbuf_addf(&sb, "refs/anchors/%s/%s", oid_to_hex(&c->object.oid), oid_to_hex(&p->item->object.oid));
			if (starts_with(item->string, sb.buf)) {
				anchor_missing = 0;
				verify_boundary_anchor(item);
			}
		}
		if (anchor_missing)
			die("missing boundary anchor reference refs/anchors/%s/%s",
				oid_to_hex(child_oid),
				oid_to_hex(&p->item->object.oid));
	}
	register_shallow(r, &o->oid);
}

/*
 * Build an annotated tag object linking a boundary <child_oid> to
 * one of its <missing_parent_oid>s.
 * If sign != 0, use existing tag signing mechanism to add gpgsig.
 * Returns 0 on success and sets result_oid.
 */
static int build_anchor_tag(const struct object_id *child_oid,
		      const struct object_id *missing_parent_oid,
		      const char *tagger_ident,
		      int sign,
		      struct object_id *result_oid)
{
	struct repository *r = the_repository;
	int ret = -1;
	enum object_type type = OBJ_COMMIT;
	struct strbuf buffer = STRBUF_INIT;
	struct object_id *compat_oid = NULL;
	struct object_id compat_oid_buf;

	if ((!child_oid) || (!missing_parent_oid) || (!tagger_ident))
		return -1;

	strbuf_addf(&buffer,
		    "object %s\n"
		    "type %s\n"
		    "tag anchor-%s-%s\n"
		    "tagger %s\n\n"
		    "anchor-parent %s\n",
		    oid_to_hex(child_oid),
		    type_name(type),
		    oid_to_hex(child_oid),
		    oid_to_hex(missing_parent_oid),
		    git_committer_info(IDENT_STRICT),
		    oid_to_hex(missing_parent_oid));

	if (r->compat_hash_algo) {
		hash_object_file(r->compat_hash_algo, buffer.buf, buffer.len,
			OBJ_TAG, &compat_oid_buf);
		compat_oid = &compat_oid_buf;
	}

	if (sign && do_sign(&buffer, &compat_oid, &compat_oid_buf) < 0)
		goto out;

	ret = odb_write_object_ext(r->objects, buffer.buf,
				   buffer.len, OBJ_TAG, result_oid, compat_oid, 0);
out:
	strbuf_release(&buffer);
	return ret;
}

/*
 * Install anchor refs:
 *   refs/anchors/<child_oid/<missing_parent_oid>
 * Ref content:
 *   <anchor_tag_oid>
 */
static void build_anchor_ref(const struct object_id *child_oid,
			      const struct object_id *missing_parent_oid,
			      const struct object_id *anchor_tag_oid)
{
	struct repository *r = the_repository;
	struct strbuf ref = STRBUF_INIT;
	strbuf_addf(&ref, "refs/anchors/%s/%s",
		    oid_to_hex(child_oid),
		    oid_to_hex(missing_parent_oid));

	if (refs_update_ref(get_main_ref_store(r), NULL, ref.buf, anchor_tag_oid,
			    NULL, 0, UPDATE_REFS_MSG_ON_ERR))
		die("could not update ref %s", ref.buf);

	strbuf_release(&ref);
}

/*
 * Create anchors (anchor tags and references) for a grafted shallow
 * boundary commit (child_oid).
 * Find commit's missing parents and build an anchor tag object and
 * anchor ref for each missing parent.
 * Also build anchor refs to all anchor tags.
 */
static void create_boundary_anchors(const struct object_id *child_oid)
{
	struct repository *r = the_repository;
	struct commit *c;
	struct object *o;
	int sign = 1; /* always try to sign, if keyid available */

	if (!child_oid)
		die("oops: (%s)", oid_to_hex(child_oid));

	o = parse_object_with_flags(r, child_oid,
						   PARSE_OBJECT_SKIP_HASH_CHECK |
						   PARSE_OBJECT_DISCARD_TREE);
	if (!o)
		die("oops: failed to get object (%s)", oid_to_hex(child_oid));

	unregister_shallow(&o->oid);
	o->parsed = 0;
	parse_commit_or_die((struct commit *)o);
	c = ((struct commit *)o);

	struct commit_list *p;
	for (p = c->parents; p; p = p->next) {
		struct object_id tag_oid;

		/* build tag object */
		if (build_anchor_tag(child_oid,
				       &p->item->object.oid,
				       git_committer_info(IDENT_STRICT),
				       sign,
				       &tag_oid) < 0) {
			die("creating anchor tag for %s -> %s failed",
				oid_to_hex(child_oid),
				oid_to_hex(&p->item->object.oid));
		}

		/* install ref: refs/anchors/<child>/<parent>: <tag_oid> */
		build_anchor_ref(child_oid, &p->item->object.oid, &tag_oid);
	}
	register_shallow(r, &o->oid);
}

static int filter_anchors_cb(const struct commit_graft *graft, void *cb_data)
{
	struct anchors_update_lists *update_anchors = (struct anchors_update_lists *)cb_data;
	struct commit *c;
	struct string_list_item *item;

	if (graft->nr_parent != -1)
		return 0;
	update_anchors->refs_to_keep.strdup_strings = 1;
	if ((c = lookup_commit(the_repository, &graft->oid))) {
		for_each_string_list_item(item, &update_anchors->refs) {
			struct strbuf sb = STRBUF_INIT;
			strbuf_addf(&sb, "refs/anchors/%s", oid_to_hex(&c->object.oid));
			if (starts_with(item->string, sb.buf)) {
				/* anchors to keep */
				string_list_insert(&update_anchors->refs_to_keep, item->string);
			}
		}
		for_each_string_list_item(item, &update_anchors->refs_to_keep) {
			string_list_remove(&update_anchors->refs, item->string, 0);
		}
	}
	return 0;
}

/*
 * Callback for each boundary commit (graft), creating necessary new
 * boundary anchors (anchor tags) or verify boundary anchors which
 * has to be kept.
 */
static int create_or_verify_anchors_cb(const struct commit_graft *graft, void *cb_data)
{
	struct string_list *refs_to_keep = (struct string_list *)cb_data;
	struct commit *c;
	struct string_list_item *item;

	if (graft->nr_parent != -1)
		return 0;

	if ((c = lookup_commit(the_repository, &graft->oid))) {
		int skip_create_for_c = 0;
		for_each_string_list_item(item, refs_to_keep) {
			struct strbuf sb = STRBUF_INIT;
			strbuf_addf(&sb, "refs/anchors/%s", oid_to_hex(&c->object.oid));
			if (!starts_with(item->string, sb.buf))
				skip_create_for_c = 1;
		}
		if (skip_create_for_c) {
			fprintf(stdout, "Verify anchors for shallow commit '%s'\n", oid_to_hex(&c->object.oid));
			verify_boundary_anchors(&c->object.oid, refs_to_keep);
		} else {
			fprintf(stdout, "Create anchors for shallow commit '%s'\n", oid_to_hex(&c->object.oid));
			create_boundary_anchors(&c->object.oid);
		}
	}
	return 0;
}

static int append_anchor_ref(const struct reference *ref, void *cb_data)
{
	struct string_list *anchor_refs = (struct string_list *)cb_data;

	if (starts_with(ref->name, "refs/anchors/"))
		string_list_append(anchor_refs, ref->name);
	return 0;
}

static int list_shallow_commits(const struct commit_graft *graft, void *cb_data)
{
	struct commit_list **shallow_commits = (struct commit_list **)cb_data;
	struct commit *c;

	if (graft->nr_parent != -1)
		return 0;

	if ((c = lookup_commit(the_repository, &graft->oid))) {
		if (!commit_list_contains(c, *shallow_commits))
			commit_list_insert(c, shallow_commits);
	} else {
		error("Shallow boundary commit object not found: '%s'", oid_to_hex(&graft->oid));
		return 1;
	}
	return 0;
}

/*
 * Check if anchors align with shallow commits.
 */
void check_anchors_alignment(void)
{
	struct ref *r;
	struct tag *item;
	struct commit_list *anchored_commits = NULL;
	struct commit_list *shallow_commits = NULL;

	for (r = get_local_heads(); r; r = r->next) {
		struct object_id anchor_tag_oid;
		if (starts_with(r->name, "refs/anchors/")) {
			struct commit *c;
			if (refs_read_ref(get_main_ref_store(the_repository), r->name, &anchor_tag_oid))
				die("cannot verify: anchor_tag '%s' not found.", r->name);
			item = lookup_tag(the_repository, &anchor_tag_oid);
			if ((c = lookup_commit(the_repository, &item->tagged->oid))) {
				if (!commit_list_contains(c, anchored_commits))
					commit_list_insert(c, &anchored_commits);
			} else {
				die("Anchored boundary commit object not found: '%s'", oid_to_hex(&item->tagged->oid));
			}
		}
	}
	for_each_commit_graft(list_shallow_commits, (void *)&shallow_commits);

	if (commit_list_count(anchored_commits) != commit_list_count(shallow_commits))
		die("\noops: number of anchored and shallow commits differ");

	struct commit_list *a, *s = shallow_commits;
	for (a = anchored_commits; a; a = a->next) {
		if (!s)
			die("\noops: anchored commit '%s' not found in shallow commits", oid_to_hex(&a->item->object.oid));
		for (s = shallow_commits; s; s = s->next)
			if (a->item == s->item)
				break;
	}

	fprintf(stdout, "Anchors aligned with shallow (grafted) commits.\n");
}

/*
 * Update all needed anchors.
 * Remove existing anchors and create new ones for each shallow
 * boundary commit.
 */
void update_anchors(void)
{
	struct anchors_update_lists update_anchors = {
		.refs = STRING_LIST_INIT_DUP,
		.refs_to_keep = STRING_LIST_INIT_DUP,
	};
	struct string_list_item *item;

	/* Get a list of current anchor refs */
	refs_for_each_ref(get_main_ref_store(the_repository),
			  append_anchor_ref, &update_anchors.refs);

	/* Get lists of anchors to keep and anchors to delete */
	for_each_commit_graft(filter_anchors_cb, (void *)&update_anchors);

	/* Remove all anchors to be deleted */
	if (refs_delete_refs(get_main_ref_store(the_repository), NULL, &update_anchors.refs, REF_NO_DEREF))
		die("oops: error deleting anchor refs");
	for_each_string_list_item(item, &update_anchors.refs) {
		const char *name = item->string;

		if (!refs_ref_exists(get_main_ref_store(the_repository), name))
			fprintf(stdout, "Deleted anchor '%s'\n", item->string + 13);
	}

	/* Create missing new or verify anchors to keep */
	for_each_commit_graft(create_or_verify_anchors_cb, (void *)&update_anchors.refs_to_keep);

	check_anchors_alignment();
	fprintf(stdout, "Anchors updated.\n");
}
