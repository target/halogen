# coding=utf-8
""" The mfbot Python3 CLI script """
from halogen.mfbot import MFBot


def main() -> None:
    """ Main function to start things up for the command line use of mfbot """
    mfbot = MFBot()
    mfbot.parse_args()
    if mfbot.dir:
        yara_rule_output = mfbot.dir_run()
        if len(yara_rule_output) > 0:
            mfbot.print_yara_rule(yara_rule_output)
        else:
            print("No images found within that directory")
    else:
        yara_rule_output = mfbot.run()
        if len(yara_rule_output) > 0:
            mfbot.print_yara_rule(yara_rule_output)
        else:
            print('No image found.')


if __name__ == "__main__":
    main()
