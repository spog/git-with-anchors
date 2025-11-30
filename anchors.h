/*
 * anchors.h
 *
 * Copyright (C) 2025, Samo Pogačnik <samo_pogacnik@t-2.net>
 *
 */

#ifndef ANCHOR_H
#define ANCHOR_H

struct anchors_update_lists {
	struct string_list refs;
	struct string_list refs_to_keep;
	struct string_list refs_to_delete;
};

/* Create and verify all needed anchors (tag ojects with refs) */
void create_anchors(void);

/* Update all needed anchors */
void update_anchors(void);

void verify_anchors(struct ref *refs, int new);

#endif /* ANCHOR_H */
