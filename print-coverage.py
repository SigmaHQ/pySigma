# Prints code testing coverage as percentage for badge generation.
from defusedxml.ElementTree import parse

tree = parse("cov.xml")
root = tree.getroot()
coverage = float(root.attrib["line-rate"]) * 100
print(f"COVERAGE={coverage:3.4}%")
if coverage >= 95.0:
    print("COVERAGE_COLOR=green")
elif coverage >= 90.0:
    print("COVERAGE_COLOR=yellow")
elif coverage >= 85.0:
    print("COVERAGE_COLOR=orange")
else:
    print("COVERAGE_COLOR=red")
