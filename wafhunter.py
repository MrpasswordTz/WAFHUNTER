from modules import*

def main():
    print(banner)
    host = input("Enter website name (without http/https): ")
    print(checking + host)
    result = check_waf(host)
    print(detection)
    print("The site", Fore.RED+host+Fore.RESET + " is Behind " + Fore.YELLOW+result+Fore.RESET)

if __name__ == "__main__":
    main()
