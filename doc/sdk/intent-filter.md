+++
title = "Start App on Hardware Discovery"

draft = false  # Is this a draft? true/false
toc = true  # Show table of contents? true/false
type = "guide"  # Do not modify.
weight = 20

# Add menu entry to sidebar.
linktitle = "Start on Hardware Discovery"
[menu.docs]
  parent = "hw-security-docs"
  weight = 20

+++

By default, the Hardware Security SDK does not register Intent filters for USB device classes and NFC Intents.
Thus, it only handles USB and NFC when your app is in the foreground.
However, if you like your app to start directly when a Security Key is discovered, you can decide to use our ``hwsecurity-intent-usb`` and ``hwsecurity-intent-nfc`` dependencies.

## USB Intent Filter
To enable USB dispatching, add the following to your ``build.gradle``:
```gradle
implementation 'de.cotech:hwsecurity-intent-usb:{{< hwsecurity-current-version >}}'
```

If included, the app will be registered for dispatching Security Keys discovered via USB.
Without this, the app will be unable to persist permission to access a USB Security Key.
To avoid asking the user for permission every time a USB Security Key connects, it is recommended to include this dependency.

## NFC Intent Filter
To enable NFC dispatching, add the following to your ``build.gradle``:
```gradle
implementation 'de.cotech:hwsecurity-intent-nfc:{{< hwsecurity-current-version >}}'
```

If included, NFC Security Key discovery will work also while the app is not in the foreground.
This is strictly optional, NFC dispatch will work with no limitations while the app is in the foreground.

## Multiple Apps Registered on the Same Intents

Keep in mind that if more than one app is registered to the USB device classes or NFC Intents, Android will show an Activity chooser to the user.

<div class="row">
<div class="col-sm-6">
{{< figure library="1" numbered="true" src="docs/usb-intent-filter.png" title="USB: The Activity chooser is shown when more than one activity has registered to the USB device classes." >}}
</div>
<div class="col-sm-6">
{{< figure library="1" numbered="true" src="docs/nfc-intent-filter.png" title="NFC: The Activity chooser is shown when more than one activity can handle the NFC Intent." >}}
</div>
</div>
