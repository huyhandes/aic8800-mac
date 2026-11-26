/*
 * aic_netsvc - add/remove a macOS network service bound to feth80 so the dongle
 * shows up in System Settings > Network (DHCP handled by configd).
 * usage: aic_netsvc install|remove|dry-run [name]
 */
#include <SystemConfiguration/SystemConfiguration.h>
#include <stdio.h>
#include <string.h>

#include "aicd_backend.h"

/* private but stable SPI (used by networksetup); lets SC model a BSD-only interface */
extern SCNetworkInterfaceRef _SCNetworkInterfaceCreateWithBSDName(CFAllocatorRef, CFStringRef, uint32_t);

static SCNetworkServiceRef find_service(SCNetworkSetRef set, CFStringRef bsd) {
    CFArrayRef svcs = SCNetworkSetCopyServices(set);
    SCNetworkServiceRef hit = NULL;
    for (CFIndex i = 0; svcs && i < CFArrayGetCount(svcs) && !hit; i++) {
        SCNetworkServiceRef s = (SCNetworkServiceRef)CFArrayGetValueAtIndex(svcs, i);
        SCNetworkInterfaceRef ifr = SCNetworkServiceGetInterface(s);
        CFStringRef n = ifr ? SCNetworkInterfaceGetBSDName(ifr) : NULL;
        if (n && CFEqual(n, bsd)) hit = (SCNetworkServiceRef)CFRetain(s);
    }
    if (svcs) CFRelease(svcs);
    return hit;
}

int main(int argc, char **argv) {
    const char *cmd = argc > 1 ? argv[1] : "";
    bool install = !strcmp(cmd, "install"), remove = !strcmp(cmd, "remove"), dry = !strcmp(cmd, "dry-run");
    if (!install && !remove && !dry) {
        fprintf(stderr, "usage: %s install|remove|dry-run [service name]\n", argv[0]);
        return 2;
    }
    CFStringRef name = CFStringCreateWithCString(NULL, argc > 2 ? argv[2] : "UGREEN WiFi", kCFStringEncodingUTF8);
    CFStringRef bsd = CFSTR(AICD_IF_HOST);

    SCPreferencesRef prefs = SCPreferencesCreate(NULL, CFSTR("aic_netsvc"), NULL);
    if (!prefs || (!dry && !SCPreferencesLock(prefs, true))) {
        fprintf(stderr, "error: cannot lock network preferences (need root): %s\n", SCErrorString(SCError()));
        return 1;
    }
    SCNetworkSetRef set = SCNetworkSetCopyCurrent(prefs);
    if (!set) { fprintf(stderr, "error: no current network set\n"); return 1; }
    SCNetworkServiceRef svc = find_service(set, bsd);

    if (remove) {
        if (!svc) { printf("no service on %s\n", AICD_IF_HOST); return 0; }
        if (!SCNetworkServiceRemove(svc)) { fprintf(stderr, "error: remove: %s\n", SCErrorString(SCError())); return 1; }
    } else if (svc) {
        printf("service already present on %s\n", AICD_IF_HOST);
        return 0;
    } else {
        SCNetworkInterfaceRef ifr = _SCNetworkInterfaceCreateWithBSDName(NULL, bsd, 0);
        svc = ifr ? SCNetworkServiceCreate(prefs, ifr) : NULL;
        if (!svc || !SCNetworkServiceSetName(svc, name) || !SCNetworkServiceEstablishDefaultConfiguration(svc) ||
            !SCNetworkSetAddService(set, svc)) {
            fprintf(stderr, "error: create service: %s\n", SCErrorString(SCError()));
            return 1;
        }
    }
    if (dry) { printf("dry-run ok: service would be created on %s\n", AICD_IF_HOST); return 0; }
    if (!SCPreferencesCommitChanges(prefs) || !SCPreferencesApplyChanges(prefs)) {
        fprintf(stderr, "error: commit: %s\n", SCErrorString(SCError()));
        return 1;
    }
    SCPreferencesUnlock(prefs);
    printf("%s service on %s\n", remove ? "removed" : "installed", AICD_IF_HOST);
    return 0;
}
