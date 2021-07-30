# Prints code testing coverage as percentage for badge generation.
import xml.etree.ElementTree as et

tree = et.parse("cov.xml")
root = tree.getroot()
coverage = float(root.attrib["line-rate"]) * 100
print(f"{coverage:.3}%")