#!/usr/bin/env python
# -*- coding: utf-8 -*-

import timelock
import sys
import pickle

if __name__ == '__main__':
	tl = timelock.new()
	fd = open("wrapper.log", "a")
	fd.write("Starting wrapper.")

	puzzle = pickle.load(sys.stdin)
	fd.write("Loaded pickled puzzle.")
	print tl.solvePuzzle(puzzle)
