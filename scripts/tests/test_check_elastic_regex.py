#!/usr/bin/env python3
"""Unit cases for scripts/check_elastic_regex.py: True means the pattern must be flagged.
Offline, standard library plus PyYAML. Run from anywhere: python scripts/tests/test_check_elastic_regex.py
Exit 0 if every case passes, 1 otherwise. Cyber-Threat.net Hunt Lab - MIT (see LICENSE).
"""
import os, sys; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from check_elastic_regex import problems as p
cases = {
 ('.*curl.*',()):False, ('.*\\s+-e.*',()):False, ('.*\\d\\w\\S.*',()):False,
 ('.*/php(-fpm|-cgi)?[0-9.]*$',()):True, ('/php(-fpm)?',()):True, ('^.*x',()):True,
 ('.*\\bfoo.*',()):True, ('.*(?i)x.*',()):True, ('.*\\$.*',()):False, ('.*\\^.*',()):False,
 ('.*[$^].*',()):False, ('.*[^]x].*',()):False, ('.*\\\\$',()):True,
 ('.*curl.*',('re','i')):True, ('.*a.*|.*b.*',()):False, ('.*a.*|b.*',()):True,
 ('.*(a|b).*',()):False, ('.*\\t.*',()):True, ('.*(a)\\1.*',()):True,
 ('.*/tmp/\\.[0-9]+( .*)?',()):False, ('.*\\\\\\.nc[0-9]+\\.js',()):False,
}
bad=0
for (pat,mods),exp in cases.items():
    got=bool(p(pat,mods))
    if got!=exp: bad+=1; print("FAIL",pat,mods,p(pat,mods))
print(f"{len(cases)-bad}/{len(cases)} passed"); sys.exit(1 if bad else 0)
