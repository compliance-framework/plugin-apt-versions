package compliance_framework.apt_versions.wget
        
violation[{
    "title": "wget version",
    "remarks": "Upgrade wget",
    "remarks": sprintf("Upgrade wget to 1.20.3, it is currently version: |%s|", [input.wget])
}] if {
    semver.compare(input.wget, "1.20.3") == -1
}
