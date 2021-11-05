/* Avoid a failing test due to libpci header symbol shadowing breakage */
#define index shadow_workaround_index
#if defined (PCIUTILS_PCI_H)
#include <pciutils/pci.h>
#else
#include <pci/pci.h>
#endif
struct pci_access *pacc;
struct pci_dev *dev = {0};
int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;
	pacc = pci_alloc();
	dev = pci_get_dev(pacc, dev->bus, dev->dev, 1);
	return 0;
}
