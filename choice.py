from art import *
from colorama import Fore, init
from src.hashNova import *
import view
import subprocess

init()

def select_file():
    """Prompt user to select a file using zenity."""
    try:
        result = subprocess.run(['zenity', '--file-selection'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        file_path = result.stdout.decode('utf-8').strip()
        if result.returncode == 0 and file_path:
            return file_path
        else:
            return None
    except Exception as e:
        print(f"{Fore.RED}Error selecting file: {e}{Fore.RESET}")
        return None

def print_options(options, columns=3):
    """Print options in a formatted manner."""
    for i, (key, option) in enumerate(options.items(), 1):
        end = '\t\t' if i % columns != 0 else '\n'
        print(option, end=end)
    if len(options) % columns != 0:
        print()

def handle_input(prompt, valid_choices):
    """Handle user input and validate choices."""
    while True:
        try:
            choice = int(input(prompt))
            if choice in valid_choices:
                return choice
            else:
                raise ValueError
        except (ValueError, TypeError):
            print(f"\n{Fore.CYAN}Wrong number value! Please select a valid option.{Fore.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Fore.CYAN}EXITED!{Fore.RESET}")
            return None

def First():
    """Main function to handle hash selection and processing."""
    print(view.line50())
    print(f"{Fore.RED}HASH selected!{Fore.RESET}")
    print(f"{Fore.CYAN}Choose the hash type: {Fore.RESET}")

    colors = {
        '[': Fore.LIGHTBLUE_EX + '[' + Fore.RESET,
        ']': Fore.LIGHTBLUE_EX + ']' + Fore.RESET,
    }

    options = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']} {Fore.RED}SHA-Family{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']} {Fore.GREEN}BLAKE-Family{Fore.RESET}",
        3: f"{colors['[']}{Fore.YELLOW}3{Fore.RESET}{colors[']']} {Fore.YELLOW}MD-Family{Fore.RESET}",
        4: f"{colors['[']}{Fore.CYAN}4{Fore.RESET}{colors[']']} {Fore.CYAN}GOST-Family{Fore.RESET}",
        5: f"{colors['[']}{Fore.MAGENTA}5{Fore.RESET}{colors[']']} {Fore.MAGENTA}SNEFRU-Family{Fore.RESET}",
        6: f"{colors['[']}{Fore.RED}6{Fore.RESET}{colors[']']} {Fore.RED}RIPEMD-Family{Fore.RESET}",
        7: f"{colors['[']}{Fore.GREEN}7{Fore.RESET}{colors[']']} {Fore.GREEN}OTHER{Fore.RESET}"
    }

    print_options(options)

    choice = handle_input(f"{Fore.CYAN}Select an option: {Fore.RESET}", options.keys())
    if choice is None:
        return

    print(view.line50())
    print(f"{Fore.CYAN}You selected: {options[choice].split(' ')[-1]}{Fore.RESET}")

    if choice == 1:
        handle_sha()
    elif choice == 2:
        handle_blake()
    elif choice == 3:
        handle_md()
    elif choice == 4:
        handle_gost()
    elif choice == 5:
        handle_snefru()
    elif choice == 6:
        handle_ripemd()
    elif choice == 7:
        handle_other()

def handle_sha():
    """Handle SHA family hash operations."""
    colors = {
        '[': Fore.LIGHTBLUE_EX + '[' + Fore.RESET,
        ']': Fore.LIGHTBLUE_EX + ']' + Fore.RESET,
    }

    optionsSHA = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']} {Fore.RED}SHA-1{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']} {Fore.GREEN}SHA-224{Fore.RESET}",
        3: f"{colors['[']}{Fore.YELLOW}3{Fore.RESET}{colors[']']} {Fore.YELLOW}SHA-256{Fore.RESET}",
        4: f"{colors['[']}{Fore.CYAN}4{Fore.RESET}{colors[']']} {Fore.CYAN}SHA-384{Fore.RESET}",
        5: f"{colors['[']}{Fore.MAGENTA}5{Fore.RESET}{colors[']']} {Fore.MAGENTA}SHA-512{Fore.RESET}",
        6: f"{colors['[']}{Fore.RED}6{Fore.RESET}{colors[']']} {Fore.RED}SHA-512-224{Fore.RESET}",
        7: f"{colors['[']}{Fore.GREEN}7{Fore.RESET}{colors[']']} {Fore.GREEN}SHA-512-256{Fore.RESET}",
        8: f"{colors['[']}{Fore.YELLOW}8{Fore.RESET}{colors[']']} {Fore.YELLOW}SHA3-224{Fore.RESET}",
        9: f"{colors['[']}{Fore.CYAN}9{Fore.RESET}{colors[']']} {Fore.CYAN}SHA3-256{Fore.RESET}",
        10: f"{colors['[']}{Fore.MAGENTA}10{Fore.RESET}{colors[']']} {Fore.MAGENTA}SHA3-384{Fore.RESET}",
        11: f"{colors['[']}{Fore.RED}11{Fore.RESET}{colors[']']} {Fore.RED}SHA3-512{Fore.RESET}",
        12: f"{colors['[']}{Fore.GREEN}12{Fore.RESET}{colors[']']} {Fore.GREEN}SHAKE-128{Fore.RESET}",
        13: f"{colors['[']}{Fore.YELLOW}13{Fore.RESET}{colors[']']} {Fore.YELLOW}SHAKE-256{Fore.RESET}",
    }

    print_options(optionsSHA, columns=3)

    choiceSHA = handle_input(f"{Fore.CYAN}Select an option: {Fore.RESET}", optionsSHA.keys())
    if choiceSHA is None:
        return

    print(view.line50())
    print(f"{Fore.CYAN}You selected: {optionsSHA[choiceSHA].split(' ')[-1]}{Fore.RESET}")

    optionsSHA_Type = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']}{Fore.RED} Hash text{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']}{Fore.GREEN} Hash file{Fore.RESET}"
    }

    print_options(optionsSHA_Type)

    choiceSHA_Type = handle_input(f"{Fore.CYAN}Select an option: {Fore.RESET}", optionsSHA_Type.keys())
    if choiceSHA_Type is None:
        return

    print(view.line50())
    print(f"{Fore.CYAN}You selected: {optionsSHA_Type[choiceSHA_Type].split(' ')[-2] + ' ' + optionsSHA_Type[choiceSHA_Type].split(' ')[-1]}{Fore.RESET}")

    if choiceSHA_Type == 1:
        try:
            text = input(f"{Fore.RED}Write the text: {Fore.RESET}")
            sha = SHA(text)
            hash_function = [
                sha.sha1_hash, sha.sha224_hash, sha.sha256_hash, sha.sha384_hash,
                sha.sha512_hash, sha.sha512_224_hash, sha.sha512_256_hash,
                sha.sha3_224_hash, sha.sha3_256_hash, sha.sha3_384_hash,
                sha.sha3_512_hash, sha.shake128_hash, sha.shake256_hash
            ][choiceSHA - 1]
            print(view.line50())
            print(f"{Fore.CYAN}The hashed text ({optionsSHA[choiceSHA].split(' ')[1]}{Fore.CYAN}): {Fore.RESET}{hash_function()}")
            print(view.line50())
        except KeyboardInterrupt:
            print(f"{Fore.CYAN}EXITED!{Fore.RESET}")

    elif choiceSHA_Type == 2:
        try:
            file_path = select_file()
            if not file_path:
                print(f"{Fore.RED}No file selected.{Fore.RESET}")
                return
            with open(file_path, 'rb') as file:
                file_content = file.read()
            sha = SHA(file_content)
            hash_function = [
                sha.sha1_hash, sha.sha224_hash, sha.sha256_hash, sha.sha384_hash,
                sha.sha512_hash, sha.sha512_224_hash, sha.sha512_256_hash,
                sha.sha3_224_hash, sha.sha3_256_hash, sha.sha3_384_hash,
                sha.sha3_512_hash, sha.shake128_hash, sha.shake256_hash
            ][choiceSHA - 1]
            print(view.line50())
            print(f"{Fore.CYAN}The hashed file ({optionsSHA[choiceSHA].split(' ')[1]}{Fore.CYAN}): {Fore.RESET}{hash_function()}")
            print(view.line50())
        except FileNotFoundError:
            print(f"{Fore.RED}File not found.{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}Error processing file: {e}{Fore.RESET}")

def handle_blake():
    """Handle BLAKE family hash operations."""
    colors = {
        '[': Fore.LIGHTBLUE_EX + '[' + Fore.RESET,
        ']': Fore.LIGHTBLUE_EX + ']' + Fore.RESET,
    }

    optionsBLAKE = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']} {Fore.RED}BLAKE2b{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']} {Fore.GREEN}BLAKE2s{Fore.RESET}",
        3: f"{colors['[']}{Fore.YELLOW}3{Fore.RESET}{colors[']']} {Fore.YELLOW}BLAKE3{Fore.RESET}",
    }

    print_options(optionsBLAKE, columns=3)

    choiceBLAKE = handle_input(f"{Fore.CYAN}Select an option: {Fore.RESET}", optionsBLAKE.keys())
    if choiceBLAKE is None:
        return

    print(view.line50())
    print(f"{Fore.CYAN}You selected: {optionsBLAKE[choiceBLAKE].split(' ')[-1]}{Fore.RESET}")

    optionsBLAKE_Type = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']}{Fore.RED} Hash text{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']}{Fore.GREEN} Hash file{Fore.RESET}"
    }

    print_options(optionsBLAKE_Type)

    choiceBLAKE_Type = handle_input(f"{Fore.CYAN}Select an option: {Fore.RESET}", optionsBLAKE_Type.keys())
    if choiceBLAKE_Type is None:
        return

    print(view.line50())
    print(f"{Fore.CYAN}You selected: {optionsBLAKE_Type[choiceBLAKE_Type].split(' ')[-2] + ' ' + optionsBLAKE_Type[choiceBLAKE_Type].split(' ')[-1]}{Fore.RESET}")

    if choiceBLAKE_Type == 1:
        try:
            text = input(f"{Fore.RED}Write the text: {Fore.RESET}")
            blake = BLAKE(text)
            hash_function = [
                blake.blake2b_hash, blake.blake2s_hash, blake.blake3_hash
            ][choiceBLAKE - 1]
            print(view.line50())
            print(f"{Fore.CYAN}The hashed text ({optionsBLAKE[choiceBLAKE].split(' ')[1]}{Fore.CYAN}): {Fore.RESET}{hash_function()}")
            print(view.line50())
        except KeyboardInterrupt:
            print(f"{Fore.CYAN}EXITED!{Fore.RESET}")

    elif choiceBLAKE_Type == 2:
        try:
            file_path = select_file()
            if not file_path:
                print(f"{Fore.RED}No file selected.{Fore.RESET}")
                return
            with open(file_path, 'rb') as file:
                file_content = file.read()
            blake = BLAKE(file_content)
            hash_function = [
                blake.blake2b_hash, blake.blake2s_hash, blake.blake3_hash
            ][choiceBLAKE - 1]
            print(view.line50())
            print(f"{Fore.CYAN}The hashed file ({optionsBLAKE[choiceBLAKE].split(' ')[1]}{Fore.CYAN}): {Fore.RESET}{hash_function()}")
            print(view.line50())
        except FileNotFoundError:
            print(f"{Fore.RED}File not found.{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}Error processing file: {e}{Fore.RESET}")

def handle_md():
    """Handle MD family hash operations."""
    colors = {
        '[': Fore.LIGHTBLUE_EX + '[' + Fore.RESET,
        ']': Fore.LIGHTBLUE_EX + ']' + Fore.RESET,
    }

    optionsMD = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']} {Fore.RED}MD2{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']} {Fore.GREEN}MD4{Fore.RESET}",
        3: f"{colors['[']}{Fore.YELLOW}3{Fore.RESET}{colors[']']} {Fore.YELLOW}MD5{Fore.RESET}",
    }

    print_options(optionsMD, columns=3)

    choiceMD = handle_input(f"{Fore.CYAN}Select an option: {Fore.RESET}", optionsMD.keys())
    if choiceMD is None:
        return

    print(view.line50())
    print(f"{Fore.CYAN}You selected: {optionsMD[choiceMD].split(' ')[-1]}{Fore.RESET}")

    optionsMD_Type = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']}{Fore.RED} Hash text{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']}{Fore.GREEN} Hash file{Fore.RESET}"
    }

    print_options(optionsMD_Type)

    choiceMD_Type = handle_input(f"{Fore.CYAN}Select an option: {Fore.RESET}", optionsMD_Type.keys())
    if choiceMD_Type is None:
        return

    print(view.line50())
    print(f"{Fore.CYAN}You selected: {optionsMD_Type[choiceMD_Type].split(' ')[-2] + ' ' + optionsMD_Type[choiceMD_Type].split(' ')[-1]}{Fore.RESET}")

    if choiceMD_Type == 1:
        try:
            text = input(f"{Fore.RED}Write the text: {Fore.RESET}")
            md = MD(text)
            hash_function = [
                md.md2_hash, md.md4_hash, md.md5_hash
            ][choiceMD - 1]
            print(view.line50())
            print(f"{Fore.CYAN}The hashed text ({optionsMD[choiceMD].split(' ')[1]}{Fore.CYAN}): {Fore.RESET}{hash_function()}")
            print(view.line50())
        except KeyboardInterrupt:
            print(f"{Fore.CYAN}EXITED!{Fore.RESET}")

    elif choiceMD_Type == 2:
        try:
            file_path = select_file()
            if not file_path:
                print(f"{Fore.RED}No file selected.{Fore.RESET}")
                return
            with open(file_path, 'rb') as file:
                file_content = file.read()
            md = MD(file_content)
            hash_function = [
                md.md2_hash, md.md4_hash, md.md5_hash
            ][choiceMD - 1]
            print(view.line50())
            print(f"{Fore.CYAN}The hashed file ({optionsMD[choiceMD].split(' ')[1]}{Fore.CYAN}): {Fore.RESET}{hash_function()}")
            print(view.line50())
        except FileNotFoundError:
            print(f"{Fore.RED}File not found.{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}Error processing file: {e}{Fore.RESET}")

def handle_gost():
    """Handle GOST family hash operations."""
    colors = {
        '[': Fore.LIGHTBLUE_EX + '[' + Fore.RESET,
        ']': Fore.LIGHTBLUE_EX + ']' + Fore.RESET,
    }

    optionsGOST = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']} {Fore.RED}GOST-94{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']} {Fore.GREEN}GOST12-256{Fore.RESET}",
        3: f"{colors['[']}{Fore.YELLOW}3{Fore.RESET}{colors[']']} {Fore.YELLOW}GOST-12-512{Fore.RESET}",
    }

    print_options(optionsGOST, columns=3)

    choiceGOST = handle_input(f"{Fore.CYAN}Select an option: {Fore.RESET}", optionsGOST.keys())
    if choiceGOST is None:
        return

    print(view.line50())
    print(f"{Fore.CYAN}You selected: {optionsGOST[choiceGOST].split(' ')[-1]}{Fore.RESET}")

    optionsGOST_Type = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']}{Fore.RED} Hash text{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']}{Fore.GREEN} Hash file{Fore.RESET}"
    }

    print_options(optionsGOST_Type)

    choiceGOST_Type = handle_input(f"{Fore.CYAN}Select an option: {Fore.RESET}", optionsGOST_Type.keys())
    if choiceGOST_Type is None:
        return

    print(view.line50())
    print(f"{Fore.CYAN}You selected: {optionsGOST_Type[choiceGOST_Type].split(' ')[-2] + ' ' + optionsGOST_Type[choiceGOST_Type].split(' ')[-1]}{Fore.RESET}")

    if choiceGOST_Type == 1:
        try:
            text = input(f"{Fore.RED}Write the text: {Fore.RESET}")
            gost = GOST(text)
            hash_function = [
                gost.gost94_hash, gost.gost12_256_hash, gost.gost12_512_hash
            ][choiceGOST - 1]
            print(view.line50())
            print(f"{Fore.CYAN}The hashed text ({optionsGOST[choiceGOST].split(' ')[1]}{Fore.CYAN}): {Fore.RESET}{hash_function()}")
            print(view.line50())
        except KeyboardInterrupt:
            print(f"{Fore.CYAN}EXITED!{Fore.RESET}")

    elif choiceGOST_Type == 2:
        try:
            file_path = select_file()
            if not file_path:
                print(f"{Fore.RED}No file selected.{Fore.RESET}")
                return
            with open(file_path, 'rb') as file:
                file_content = file.read()
            gost = GOST(file_content)
            hash_function = [
                gost.gost94_hash, gost.gost12_256_hash, gost.gost12_512_hash
            ][choiceGOST - 1]
            print(view.line50())
            print(f"{Fore.CYAN}The hashed file ({optionsGOST[choiceGOST].split(' ')[1]}{Fore.CYAN}): {Fore.RESET}{hash_function()}")
            print(view.line50())
        except FileNotFoundError:
            print(f"{Fore.RED}File not found.{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}Error processing file: {e}{Fore.RESET}")

def handle_snefru():
    """Handle SNEFRU family hash operations."""
    colors = {
        '[': Fore.LIGHTBLUE_EX + '[' + Fore.RESET,
        ']': Fore.LIGHTBLUE_EX + ']' + Fore.RESET,
    }

    optionsSNEFRU = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']} {Fore.RED}SNEFRU-128{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']} {Fore.GREEN}SNEFRU-256{Fore.RESET}",
    }

    print_options(optionsSNEFRU, columns=3)

    choiceSNEFRU = handle_input(f"{Fore.CYAN}Select an option: {Fore.RESET}", optionsSNEFRU.keys())
    if choiceSNEFRU is None:
        return

    print(view.line50())
    print(f"{Fore.CYAN}You selected: {optionsSNEFRU[choiceSNEFRU].split(' ')[-1]}{Fore.RESET}")

    optionsSNEFRU_Type = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']}{Fore.RED} Hash text{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']}{Fore.GREEN} Hash file{Fore.RESET}"
    }

    print_options(optionsSNEFRU_Type)

    choiceSNEFRU_Type = handle_input(f"{Fore.CYAN}Select an option: {Fore.RESET}", optionsSNEFRU_Type.keys())
    if choiceSNEFRU_Type is None:
        return

    print(view.line50())
    print(f"{Fore.CYAN}You selected: {optionsSNEFRU_Type[choiceSNEFRU_Type].split(' ')[-2] + ' ' + optionsSNEFRU_Type[choiceSNEFRU_Type].split(' ')[-1]}{Fore.RESET}")

    if choiceSNEFRU_Type == 1:
        try:
            text = input(f"{Fore.RED}Write the text: {Fore.RESET}")
            snefru = SNEFRU(text)
            hash_function = [
                snefru.snefru128_hash, snefru.snefru256_hash
            ][choiceSNEFRU - 1]
            print(view.line50())
            print(f"{Fore.CYAN}The hashed text ({optionsSNEFRU[choiceSNEFRU].split(' ')[1]}{Fore.CYAN}): {Fore.RESET}{hash_function()}")
            print(view.line50())
        except KeyboardInterrupt:
            print(f"{Fore.CYAN}EXITED!{Fore.RESET}")

    elif choiceSNEFRU_Type == 2:
        try:
            file_path = select_file()
            if not file_path:
                print(f"{Fore.RED}No file selected.{Fore.RESET}")
                return
            with open(file_path, 'rb') as file:
                file_content = file.read()
            snefru = SNEFRU(file_content)
            hash_function = [
                snefru.snefru128_hash, snefru.snefru256_hash
            ][choiceSNEFRU - 1]
            print(view.line50())
            print(f"{Fore.CYAN}The hashed file ({optionsSNEFRU[choiceSNEFRU].split(' ')[1]}{Fore.CYAN}): {Fore.RESET}{hash_function()}")
            print(view.line50())
        except FileNotFoundError:
            print(f"{Fore.RED}File not found.{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}Error processing file: {e}{Fore.RESET}")

def handle_ripemd():
    """Handle RIPEMBD family hash operations."""
    colors = {
        '[': Fore.LIGHTBLUE_EX + '[' + Fore.RESET,
        ']': Fore.LIGHTBLUE_EX + ']' + Fore.RESET,
    }

    optionsRIPEMD = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']} {Fore.RED}RIPEMD-128{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']} {Fore.GREEN}RIPEMD-160{Fore.RESET}",
        3: f"{colors['[']}{Fore.YELLOW}3{Fore.RESET}{colors[']']} {Fore.YELLOW}RIPEMD-256{Fore.RESET}",
        4: f"{colors['[']}{Fore.CYAN}4{Fore.RESET}{colors[']']} {Fore.CYAN}RIPEMD-320{Fore.RESET}"
    }

    print_options(optionsRIPEMD, columns=3)

    choiceRIPEMD = handle_input(f"{Fore.CYAN}Select an option: {Fore.RESET}", optionsRIPEMD.keys())
    if choiceRIPEMD is None:
        return

    print(view.line50())
    print(f"{Fore.CYAN}You selected: {optionsRIPEMD[choiceRIPEMD].split(' ')[-1]}{Fore.RESET}")

    optionsRIPEMD_Type = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']}{Fore.RED} Hash text{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']}{Fore.GREEN} Hash file{Fore.RESET}"
    }

    print_options(optionsRIPEMD_Type)

    choiceRIPEMD_Type = handle_input(f"{Fore.CYAN}Select an option: {Fore.RESET}", optionsRIPEMD_Type.keys())
    if choiceRIPEMD_Type is None:
        return

    print(view.line50())
    print(f"{Fore.CYAN}You selected: {optionsRIPEMD_Type[choiceRIPEMD_Type].split(' ')[-2] + ' ' + optionsRIPEMD_Type[choiceRIPEMD_Type].split(' ')[-1]}{Fore.RESET}")

    if choiceRIPEMD_Type == 1:
        try:
            text = input(f"{Fore.RED}Write the text: {Fore.RESET}")
            ripemd = RIPEMD(text)
            hash_function = [
                ripemd.ripemd128_hash, ripemd.ripemd160_hash, ripemd.ripemd256_hash, ripemd.ripemd320_hash
            ][choiceRIPEMD - 1]
            print(view.line50())
            print(f"{Fore.CYAN}The hashed text ({optionsRIPEMD[choiceRIPEMD].split(' ')[1]}{Fore.CYAN}): {Fore.RESET}{hash_function()}")
            print(view.line50())
        except KeyboardInterrupt:
            print(f"{Fore.CYAN}EXITED!{Fore.RESET}")

    elif choiceRIPEMD_Type == 2:
        try:
            file_path = select_file()
            if not file_path:
                print(f"{Fore.RED}No file selected.{Fore.RESET}")
                return
            with open(file_path, 'rb') as file:
                file_content = file.read()
            ripemd = RIPEMD(file_content)
            hash_function = [
                ripemd.ripemd128_hash, ripemd.ripemd160_hash, ripemd.ripemd256_hash, ripemd.ripemd320_hash
            ][choiceRIPEMD - 1]
            print(view.line50())
            print(f"{Fore.CYAN}The hashed file ({optionsRIPEMD[choiceRIPEMD].split(' ')[1]}{Fore.CYAN}): {Fore.RESET}{hash_function()}")
            print(view.line50())
        except FileNotFoundError:
            print(f"{Fore.RED}File not found.{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}Error processing file: {e}{Fore.RESET}")

def handle_other():
    """Handle other hash operations."""
    print(f"{Fore.CYAN}Other hash types not yet implemented.{Fore.RESET}")