with open('network_security_scanner/frontend/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

old = 'custom-select-options">\n                      <div class="custom-option" data-value="deep">\U0001f52c Deep Scan \u2014 Versions, OS fingerprint & SSL</div>\n                      <div class="custom-option" data-value="inventory">\U0001f4cb Inventory Verify \u2014 Re-check known devices & offline states</div>\n                      <div class="custom-option" data-value="audit">\U0001f6e1\ufe0f Security Audit \u2014 NSE scripts, weak protocols & CVE matches</div>\n                    </div>'

new = 'custom-select-options">\n                      <div class="custom-option" data-value="quick">\u26a1 Quick Discover</div>\n                      <div class="custom-option selected" data-value="standard">\U0001f50d Standard Scan</div>\n                      <div class="custom-option" data-value="deep">\U0001f52c Deep Scan</div>\n                      <div class="custom-option" data-value="inventory">\U0001f4cb Inventory Verify</div>\n                      <div class="custom-option" data-value="audit">\U0001f6e1\ufe0f Security Audit</div>\n                    </div>'

if old in content:
    content = content.replace(old, new)
    with open('network_security_scanner/frontend/index.html', 'w', encoding='utf-8') as f:
        f.write(content)
    print('SUCCESS: Dropdown options fixed')
else:
    print('MISMATCH: Could not find exact string')
