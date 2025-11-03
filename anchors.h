/*
 * anchors.h
 *
 * Copyright (C) 2025, Samo Pogačnik <samo_pogacnik@t-2.net>
 *
 */

#ifndef ANCHOR_H
#define ANCHOR_H

/* Create an anchor tag object (helper) */
int create_anchor_tag(const struct object_id *child_oid,
		      const struct object_id *missing_parent_oid,
		      const char *tagger_ident,
		      int sign,
		      struct object_id *result_oid);

/* Create anchors (tag ojects with refs) for one shallow boundry commit */
void create_anchors_v2(const struct object_id *child_oid);

/* Create all anchors (tag ojects with refs) */
void create_anchors(struct shallow_info *info);

#endif /* ANCHOR_H */
