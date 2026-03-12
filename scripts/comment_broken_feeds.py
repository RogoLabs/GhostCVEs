#!/usr/bin/env python3
"""
Comment out broken RSS feeds in config.py

Adds # BROKEN: prefix to feeds that return 404/403/parse errors.
This is safer than removing - we can easily uncomment if fixes are found.
"""

BROKEN_FEEDS = {
    "Red Hat RHSA RSS": "404 - Duplicate of JSON API",
    "NVD CVE Feed": "403 - Deprecated JSON feeds",
    "Mozilla Security Advisories": "404",
    "Apple Security Updates": "Not RSS/Parse error",
    "Android Security Bulletins": "Not RSS/Parse error",
    "Linux Kernel CVE Announce": "Parse error",
    "Oracle Security Alerts": "404",
    "VMware Security Advisories": "Parse error",
    "SAP Security Patch Day": "404",
    "Atlassian Security Advisories": "Parse error",
    "Palo Alto Networks Security Advisories": "DNS resolution failed",
    "Intel Security Center": "403 - Not RSS",
    "AMD Security Bulletins": "Not RSS/Parse error",
    "NVIDIA Security Bulletins": "Not RSS/Parse error",
    "Qualcomm Security Bulletins": "Not RSS/Parse error",
    "OpenSSL Security Advisories": "404 - URL changed",
    "curl Security Advisories": "Parse error",
    "Python Security Announcements": "Parse error",
    "Siemens ProductCERT": "Parse error",
    "Schneider Electric Security Notifications": "Parse error",
    "Samsung Mobile Security": "Parse error",
    "NETGEAR Security Advisories": "Parse error",
    "TP-Link Security Advisories": "Parse error",
    "Zoom Security Bulletins": "Parse error",
}

def comment_out_broken_feeds():
    """Comment out broken feeds in config.py"""

    with open("src/config.py", "r") as f:
        lines = f.readlines()

    new_lines = []
    in_broken_feed = False
    broken_feed_name = None
    commented_feeds = []

    for i, line in enumerate(lines):
        # Check if this line starts a RSSFeed block
        if "RSSFeed(" in line and not line.strip().startswith("#"):
            in_broken_feed = False
            broken_feed_name = None

            # Look ahead to find the name
            for j in range(i, min(i + 5, len(lines))):
                if 'name="' in lines[j]:
                    # Extract feed name
                    name_start = lines[j].find('name="') + 6
                    name_end = lines[j].find('"', name_start)
                    feed_name = lines[j][name_start:name_end]

                    if feed_name in BROKEN_FEEDS:
                        in_broken_feed = True
                        broken_feed_name = feed_name
                        reason = BROKEN_FEEDS[feed_name]
                        # Add comment explaining why it's broken
                        new_lines.append(f"    # BROKEN ({reason}):\n")
                        commented_feeds.append((feed_name, reason))
                    break

        # Comment out the line if we're in a broken feed block
        if in_broken_feed:
            if line.strip() and not line.strip().startswith("#"):
                new_lines.append("    # " + line.lstrip())
            else:
                new_lines.append(line)

            # Check if this is the end of the RSSFeed block
            if ")," in line:
                in_broken_feed = False
                broken_feed_name = None
        else:
            new_lines.append(line)

    # Write back
    with open("src/config.py", "w") as f:
        f.writelines(new_lines)

    return commented_feeds

if __name__ == "__main__":
    print("=" * 70)
    print("Commenting Out Broken RSS Feeds")
    print("=" * 70)

    commented = comment_out_broken_feeds()

    print(f"\n✅ Commented out {len(commented)} broken feeds:\n")
    for feed, reason in sorted(commented):
        print(f"  • {feed}")
        print(f"    Reason: {reason}")

    print(f"\n📊 Summary:")
    print(f"  Total commented: {len(commented)}")
    print(f"  Working feeds remain active: ~15")
    print("\n✅ Config updated - broken feeds commented out but preserved")
