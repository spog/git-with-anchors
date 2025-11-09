/*
 * anchors.h
 *
 * Copyright (C) 2025, Samo Pogačnik <samo_pogacnik@t-2.net>
 *
 */

#ifndef ANCHOR_H
#define ANCHOR_H

/* Create all needed anchors (tag ojects with refs) */
void create_anchors(struct ref *refs);

void verify_anchors(struct ref *refs, int new);

#endif /* ANCHOR_H */
