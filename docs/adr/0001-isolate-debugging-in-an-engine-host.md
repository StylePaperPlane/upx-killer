# Isolate target debugging in a single-job Engine Host

The WinUI process delegates each unpacking run to a short-lived Engine Host over versioned anonymous pipes. This keeps the same-thread Windows debugger protocol and untrusted target lifetime out of the UI process, while a kill-on-close Job guarantees cleanup if either the UI connection or Host fails; the additional executable and protocol versioning are accepted deployment costs.
