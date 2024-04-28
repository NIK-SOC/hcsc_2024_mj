#!/bin/sh

sqlite3 messages.db <<EOF
CREATE TABLE messages (name TEXT, message TEXT);
INSERT INTO messages VALUES ('Alice', 'Hello Alice!');
INSERT INTO messages VALUES ('Bob', 'Hello Bob!');
INSERT INTO messages VALUES ('Eve', 'Hello Eve!');
CREATE TABLE flag (flag TEXT);
INSERT INTO flag VALUES ('HCSC24{h0pe_y0u_u53d_the_str1nG_1n_pR3qu3l_4nd_n0t_b0ring_r34d}');
EOF