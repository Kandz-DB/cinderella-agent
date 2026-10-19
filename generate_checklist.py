#!/usr/bin/env python3
"""
Generates a populated Leave Handover Checklist docx from the template.
Called by Node.js: python3 generate_checklist.py <json_data>
Outputs base64-encoded docx to stdout.
"""
import sys, json, zipfile, io, re, base64

data = json.loads(sys.argv[1])

template_paths = [
    '/home/leave-checklist-template.docx',
    '/home/site/wwwroot/leave-checklist-template.docx',
]
template_bytes = None
for p in template_paths:
    try:
        with open(p, 'rb') as f:
            template_bytes = f.read()
        break
    except:
        pass

if not template_bytes:
    sys.exit("Template not found")

# Read template
zin = zipfile.ZipFile(io.BytesIO(template_bytes))
doc_xml = zin.read('word/document.xml').decode('utf-8')

# ── Fill in header details ──
staff_name     = data.get('staffName', '[Insert name]')
staff_role     = data.get('staffRole', '[Insert position]')
start_date     = data.get('startDate', '[Insert date]')
end_date       = data.get('endDate', '[Insert date]')
cover          = data.get('coveringColleague', '[Insert name]')
manager        = data.get('manager', 'Kandia Du Bruyn')
sp             = data.get('sharepointLinks', {})

# Replace header table placeholders in order of appearance
# Each [Insert name] maps to: staff member, covering colleague, phase1 signer, phase2 signer, phase3 signer
name_replacements = [
    staff_name,    # Staff Member Going on Leave
    staff_role,    # Position — we do this separately
    start_date,    # Leave Start Date
    end_date,      # Leave End Date
    cover,         # Covering Colleague
    manager,       # Manager
    staff_name,    # Phase 1 signer name
    cover,         # Phase 2 signer name
    manager,       # Phase 3 signer name
]

# Replace [Insert position] first
doc_xml = doc_xml.replace('[Insert position]', staff_role, 1)

# Replace [Insert date] — first occurrence = start, second = end
doc_xml = doc_xml.replace('[Insert date]', start_date, 1)
doc_xml = doc_xml.replace('[Insert date]', end_date, 1)

# Replace [Insert name] in order
for replacement in [staff_name, cover, manager, staff_name, cover, manager]:
    doc_xml = doc_xml.replace('[Insert name]', replacement, 1)

# Replace SharePoint links
sp_fields = ['masterFolder', 'clientFolder', 'templates', 'correspondence', 'other']
for field in sp_fields:
    link = sp.get(field, '')
    if link:
        doc_xml = doc_xml.replace('[Insert SharePoint link]', link, 1)
    else:
        doc_xml = doc_xml.replace('[Insert SharePoint link]', '[Not yet provided]', 1)

# ── Tick completed checklist items ──
checklist = data.get('checklist', {})
# Map checklist item IDs to their position in the ☐ sequence
ITEM_ORDER = [
    'contacts', 'access', 'external',          # Section 1 (positions 0,1,2)
    'status', 'deadlines', 'stalling',          # Section 2 (positions 3,4,5)
    'sharepoint', 'sp_verified',                # Section 3 (positions 6,7)
    'decisions', 'risks',                       # Section 4 (positions 8,9)
    'discussion', 'understood', 'emergency',    # Section 5 (positions 10,11,12)
]

# Replace ☐ with ☑ for completed items
for i, item_id in enumerate(ITEM_ORDER):
    if checklist.get(item_id):
        # Replace the i-th occurrence of ☐ with ☑
        count = 0
        pos = 0
        while True:
            idx = doc_xml.find('☐', pos)
            if idx == -1:
                break
            if count == i:
                doc_xml = doc_xml[:idx] + '☑' + doc_xml[idx+1:]
                break
            count += 1
            pos = idx + 1

# Add digital signatures for signed phases
phase_sigs = {
    'phase1_signed': staff_name,
    'phase2_signed': cover,
    'phase3_signed': manager
}
for phase_key, signer_name in phase_sigs.items():
    if checklist.get(phase_key):
        # Find the signer's name in the signature rows and add SIGNED
        doc_xml = doc_xml.replace(
            f'>{signer_name}</w:t>',
            f'>{signer_name} — DIGITALLY SIGNED BY CINDERELLA</w:t>',
            1
        )

# ── Build output docx ──
output = io.BytesIO()
with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        if item.filename == 'word/document.xml':
            zout.writestr(item, doc_xml.encode('utf-8'))
        else:
            zout.writestr(item, zin.read(item.filename))

print(base64.b64encode(output.getvalue()).decode('utf-8'))
