# Distinguish Drift from Outdated using Deployment history

A mismatch between a Device's Presented Certificate and its assigned Certificate happens routinely after every renewal, so treating it as a purge would raise a false alarm on every Device each time. We classify a Presented Certificate whose fingerprint matches a Certificate previously deployed to that Device as Outdated (redeployed quietly) and anything else as Drift (alarm and webhook). This requires keeping Superseded Certificates and the Deployment history.
