python3 preprocesser.py
python3 src_obf.py
make
python3 isa_obf.py
python3 sprinkle_symbol.py ./main_obf ./chall --min-step 0x50 --max-step 0x100