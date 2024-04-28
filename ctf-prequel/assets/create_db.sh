#!/bin/sh

sqlite3 messages.db <<EOF
CREATE TABLE messages (name TEXT, message TEXT);
INSERT INTO messages VALUES ('Alice', 'Hello Alice!');
INSERT INTO messages VALUES ('Bob', 'Hello Bob!');
INSERT INTO messages VALUES ('Eve', 'Hello Eve!');
CREATE TABLE flag (flag TEXT);
INSERT INTO flag VALUES ('HCSC24{wh3n_y0ur_');
INSERT INTO flag VALUES ('str1ngs_4r3_thE_M0st');
INSERT INTO flag VALUES ('pr3c1ous_g4dG3t5}');
EOF

sqlite3 messages_debug.db <<EOF
CREATE TABLE messages (name TEXT, message TEXT);
INSERT INTO messages VALUES ('Alice', 'Hello Alice!');
INSERT INTO messages VALUES ('Bob', 'Hello Bob!');
INSERT INTO messages VALUES ('Eve', 'Hello Eve!');
CREATE TABLE flag (flag TEXT);
INSERT INTO flag VALUES ('HCSC24{this_is');
INSERT INTO flag VALUES ('_a_fake_');
INSERT INTO flag VALUES ('flag}');
EOF