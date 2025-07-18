import pathlib

base_path = pathlib.Path(__file__).parent.parent.parent / "files"

def print_header(text: str, length: int):
    side = '='*length
    print(f'{side} {text} {side}')

