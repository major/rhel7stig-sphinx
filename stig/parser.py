#!/usr/bin/env python
"""Parse RHEL 7 STIG XCCDF file into Sphinx docs."""
import os

import jinja2


from lxml import etree


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
XCCDF_FILE = 'U_Red_Hat_Enterprise_Linux_7_STIG_V1R0-2_Manual-xccdf.xml'
# XCCDF_FILE = 'U_RedHat_6_V1R8_Manual-xccdf.xml'


def write_file(filename, content):
    """Write a file to disk."""
    dirname = os.path.dirname(filename)
    if not os.path.isdir(dirname):
        os.makedirs(dirname)

    with open(filename, 'w') as f:
        f.write(content.encode('utf-8'))


def description_tag_prettify(uglyname):
    """Make description tags prettier."""
    if uglyname is None or isinstance(uglyname, jinja2.Undefined):
        return uglyname

    prettynames = {
        'SecurityOverrideGuidance': 'Security Override Guidance',
        'MitigationControl': 'Mitigation Control',
        'IAControls': 'IA Controls',
        'FalseNegatives': 'False Negatives',
        'Mitigations': 'Mitigations',
        'ThirdPartyTools': 'Third Party Tools',
        'Responsibility': 'Responsibility',
        'PotentialImpacts': 'Potential Impacts',
        'FalsePositives': 'False Positives',
        'Documentable': 'Documentable'
    }

    if uglyname in prettynames:
        return prettynames[uglyname]
    else:
        return uglyname

# Get Jinja configured properly
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(SCRIPT_DIR)
)
jinja_env.filters['prettydesc'] = description_tag_prettify

# Read in the giant XCCDF file
with open("{0}/{1}".format(SCRIPT_DIR, XCCDF_FILE), 'r') as f:
    tree = etree.parse(f)

# Set our default namespace for this XML document
namespaces = {'x': 'http://checklists.nist.gov/xccdf/1.1'}

# Get the document title/version
title = tree.xpath("/x:Benchmark/x:title", namespaces=namespaces)[0].text
version = tree.xpath("/x:Benchmark/x:plain-text",
                     namespaces=namespaces)[0].text


# Loop through the groups and extract information about rules
group_elements = tree.xpath("/x:Benchmark/x:Group", namespaces=namespaces)
rules = []
for group_element in group_elements:
    rule_element = group_element.find('x:Rule', namespaces=namespaces)
    rule = dict(rule_element.attrib)

    # Overwrite rule_id with the id from the parent group to make things easier
    rule['id'] = group_element.attrib['id']

    rule['title'] = rule_element.find('x:title', namespaces=namespaces).text
    rule['fix'] = rule_element.find('x:fixtext',
                                    namespaces=namespaces).text
    rule['check'] = rule_element.find('x:check/x:check-content',
                                      namespaces=namespaces).text
    rule['ident'] = [x.text for x in
                     rule_element.findall('x:ident', namespaces=namespaces)]

    # The description has badly formed XML in it, so we need to hack it up and
    # turn those tags into a dictionary.
    description = rule_element.find('x:description',
                                    namespaces=namespaces).text.encode('utf-8')

    parser = etree.XMLParser(recover=True)
    temp = etree.fromstring("<root>{0}</root>".format(description), parser)
    rule['description'] = {x.tag: x.text for x in temp.iter()}

    # Generate RST and write it to disk
    # rst_output = jinja_env.get_template("rule_template.j2").render(
    #     rule=rule,
    # )
    # write_file('doc/source/rules/{0}.rst'.format(rule['id']), rst_output)

    rules.append(rule)

for severity in ['low', 'medium', 'high']:
    valid_rules = [x for x in rules if x['severity'] == severity]

    # Generate RST and write it to disk
    rst_output = jinja_env.get_template("rule_template.j2").render(
        rules=valid_rules,
        severity=severity,
    )
    write_file('doc/source/{0}.rst'.format(severity), rst_output)

# Generate the index file RST and write it to disk
rst_output = jinja_env.get_template("index.j2").render(
    # profiles=profiles,
    rules=rules,
    title=title,
    version=version,
)
write_file('doc/source/index.rst', rst_output)
