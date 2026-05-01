import subprocess
import re

html = subprocess.check_output(['git', 'show', '4efb483:frontend/index.html']).decode('utf-8')
js = subprocess.check_output(['git', 'show', '4efb483:frontend/src/dashboard.js']).decode('utf-8')

# Extract HTML panels
cspm = re.search(r'<section id="cspm-panel.*?<\/section>', html, re.DOTALL)
container = re.search(r'<section id="container-panel.*?<\/section>', html, re.DOTALL)
compliance = re.search(r'<section id="compliance-panel.*?<\/section>', html, re.DOTALL)

with open('panels.html', 'w', encoding='utf-8') as f:
    if cspm: f.write(cspm.group(0) + '\n\n')
    if container: f.write(container.group(0) + '\n\n')
    if compliance: f.write(compliance.group(0) + '\n\n')

# We can also just extract all the missing JS functions from 4efb483 dashboard.js
# But since 4efb483 dashboard.js is fully self contained for CSPM/Containers,
# we can just serve it as a separate module, OR just concatenate the functions.
# Let's save the ENTIRE dashboard.js from 4efb483 to `cspm_full.js`
# and we will tell the user to use it if they want.

with open('frontend/src/cspm_full.js', 'w', encoding='utf-8') as f:
    f.write(js)

print("Extraction complete.")
