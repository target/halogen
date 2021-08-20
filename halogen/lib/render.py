# coding=utf-8
""" The render library to support all output processes  """
import datetime


def yara_print_rule(self, l):
    """ iterate over the list, and print a string for each rule
    parameter: l - list of rules"""
    if self.name:
        rname = str(self.name)
    else:
        rname = "halo_generated_{md5_hash}".format(md5_hash=self.get_file[0])
    if self.dirhash:
        md5val = self.dirhash
    else:
        md5val = self.get_file[0]
    if self.dir:
        fname = "Directory: {0}".format(self.dir)
    else:
        fname = self.yara_base_file

    rule_string = """\
rule {rname} : maldoc image
{{
    meta:
        tlp = "amber"
        author = "Halogen Generated Rule"
        date = "{date}"
        md5 = "{md5_hash}"
        family = "malware family"
        filename = "{input_file}"
        scope = "['detection', 'collection']"
        intel = "['']"
    strings:
""".format(rname=rname, md5_hash=md5val, date=str(datetime.date.today()),
           input_file=fname)
    for i in range(0, len(l)):
        rule_dict = l[i]
        ftype = rule_dict['format'].lower()
        image_hex = rule_dict['hex']
        s = "        ${ftype}_img_value_{image_name_string} = {{{image_value_str}}}\n".format(
            ftype=ftype, image_name_string=i, image_value_str=image_hex
        )
        rule_string += s

    rule_string += """
    condition:
        any of them
}"""
    print(rule_string)
