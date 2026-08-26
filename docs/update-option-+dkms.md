# Update option: BPF LSM + DKMS and LSM + DKMS

This is a upgrade to (BPF) LSM option.
My understanding is that once + DKMS is added, it makes most of the features from (BPF) LSM redundent/wasted.

## Intended role

(BPF) LSM provides the usable first backend: static Allow/Deny enforcement where existing LSM hook exists.
Fanotify remains responsible for the current interactive Open and File Execute path.

The custom kernel (+DKMS) later supplies prompting functionality.

# Note

In all future update plans, when i say + dkms, i mean either directly editing the kernel or using klp-build, the method of "delivery" can be decided later.