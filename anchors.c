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

static int do_sign(struct strbuf *buffer, struct object_id **compat_oid,
		   struct object_id *compat_oid_buf)
{
	struct repository *r = the_repository;
	const struct git_hash_algo *compat = r->compat_hash_algo;
	struct strbuf sig = STRBUF_INIT, compat_sig = STRBUF_INIT;
	struct strbuf compat_buf = STRBUF_INIT;
	char *keyid = get_signing_key();
	int ret = -1;

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

/*
 * Create an annotated tag object linking a boundry <child_oid> to
 * one of its <missing_parent_oid>s.
 * If sign != 0, use existing tag signing mechanism to add gpgsig.
 * Returns 0 on success and sets result_oid.
 */
static int create_anchor_tag(const struct object_id *child_oid,
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
static void create_anchor_ref(const struct object_id *child_oid,
			      const struct object_id *missing_parent_oid,
			      const struct object_id *anchor_tag_oid)
{
	struct repository *r = the_repository;
	struct strbuf ref = STRBUF_INIT;
	strbuf_addf(&ref, "refs/anchors/%s/%s",
		    oid_to_hex(child_oid),
		    oid_to_hex(missing_parent_oid));

	if (refs_update_ref(get_main_ref_store(r), NULL, ref.buf, anchor_tag_oid,
			    NULL, REF_NO_DEREF, UPDATE_REFS_MSG_ON_ERR))
		die("could not update ref %s", ref.buf);

	strbuf_release(&ref);
}

/*
 * Create anchors (anchor tags and references) for a shallow boundary
 * commit (child_oid).
 */
static void create_boundry_anchors(const struct object_id *child_oid)
{
	struct repository *r = the_repository;
	struct commit *c;
	struct object *o;
	int sign = 0; /* honor user signing config if desired */

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

		/* create tag object */
		if (create_anchor_tag(child_oid,
				       &p->item->object.oid,
				       git_committer_info(IDENT_STRICT),
				       sign,
				       &tag_oid) < 0) {
			die("creating anchor tag for %s -> %s failed",
				oid_to_hex(child_oid),
				oid_to_hex(&p->item->object.oid));
		}

		/* install ref: refs/anchors/<child>/<parent>: <tag_oid> */
		create_anchor_ref(child_oid, &p->item->object.oid, &tag_oid);
	}
	register_shallow(r, &o->oid);
}

static int create_one_anchor(const struct commit_graft *graft, void *cb_data)
{
	struct commit *c;
	if (graft->nr_parent != -1)
		return 0;

	if ((c = lookup_commit(the_repository, &graft->oid)))
		create_boundry_anchors(&c->object.oid);
	return 0;
}

/*
 * For each shallow boundary commit, find missing parents and create
 * an anchor tag object for each missing parent linking the child
 * (boundry commit) to its missing parentis.
 * Also create anchor refs to all anchor tags.
 */
void create_anchors(void)
{
	for_each_commit_graft(create_one_anchor, NULL);
}
