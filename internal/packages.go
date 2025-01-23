package internal

type PackageVersions map[string]interface{}

type PackageVersionCollector interface {
	GetInstalledPackages() (PackageVersions, string, error)
}
