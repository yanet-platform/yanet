 /*
 * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
 * http://burtleburtle.net/bob/hash/
 *
 * Sources taken from Linux kernel implementation.
 * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * Turned into userspace program by avd
 * Copyright (C) 2014 Alex Dzyoba <avd@reduct.ru>
 *  
 * This code as original Bob's code is in public domain.
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

inline uint32_t jenkins_hash(const uint8_t* key, size_t length) {
  size_t i = 0;
  uint32_t hash = 0;
  while (i != length) {
    hash += key[i++];
    hash += hash << 10;
    hash ^= hash >> 6;
  }
  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;
  return hash;
}