from flask import Blueprint, request, render_template, flash, redirect, url_for
from .modules import passive_osint, port_scan, web_enum, cve_scan
import os

main = Blueprint("main", __name__)

@main.route("/")
def index():
    return render_template("index.html")

@main.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target")
    if not target or target.strip() == "":
        flash("Please enter a valid target.", "error")
        return redirect(url_for("main.index"))
    try:
        subdomains = passive_osint.get_subdomains_crtsh(target)
        ports = port_scan.run_nmap(target)
        web = web_enum.httpx_fingerprint(target)
        cve = cve_scan.run_nuclei(target)
        summary = cve_scan.summarize_findings(cve)

        # Create directory for this scan results
        base_dir = os.path.join("scan_results", target.replace("/", "_"))
        os.makedirs(base_dir, exist_ok=True)

        # Save each scan result to separate .txt files
        with open(os.path.join(base_dir, "subdomains.txt"), "w") as f:
            if isinstance(subdomains, list):
                f.write("\n".join(subdomains))
            else:
                f.write(str(subdomains))

        with open(os.path.join(base_dir, "ports.txt"), "w") as f:
            f.write(str(ports))

        with open(os.path.join(base_dir, "web_enum.txt"), "w") as f:
            f.write(str(web))

        with open(os.path.join(base_dir, "cve.txt"), "w") as f:
            f.write(str(cve))

        with open(os.path.join(base_dir, "summary.txt"), "w") as f:
            f.write(str(summary))

    except Exception as e:
        flash(f"An error occurred during scanning: {str(e)}", "error")
        return redirect(url_for("main.index"))

    return render_template("report.html", target=target, subs=subdomains, ports=ports, web=web, cves=cve, summary=summary)
