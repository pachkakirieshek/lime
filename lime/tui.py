def confirm(level, reasons):
    print(f"Risk: {level}")
    print("Reasons:", reasons)

    ans = input("Are you sure? [y/n]: ")

    return ans.lower() == "y"