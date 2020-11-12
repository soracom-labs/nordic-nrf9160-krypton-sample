.. _krypton_client:

nRF9160: Krypton Client
#####################

The Krypton Client sample demonstrates downloading AWS IoT certificates from Soracom Krypton.
It shows how to set up a TLS session towards an HTTPS server and how to send an HTTP request.
It also shows how to store certificates into the modem using the nrfConnect Modem Key Management Library 
and how to set up a MQTTS connection to a host endpoint using the stored certificates. 

Overview
********

The sample first initializes the :ref:`nrfxlib:bsdlib` and AT communications.
Next, it provisions a root CA certificate to the modem using the :ref:`modem_key_mgmt` library.
Provisioning must be done before connecting to the LTE network, because the certificates can only be provisioned when the device is not connected.

The sample then establishes a connection to the LTE network, sets up the necessary TLS socket options, and connects to the Krypton server.
It uses the lightweight version of Soracom Krypton to first download the private key and store information like the certificate ID, mqtt hostname, 
and mqtt client ID.

The modem is set to offline state so that the certificates can be stored to the modem again using the :ref:`modem_key_mgmt` library.

The modem is turned back to the online state and proceeds to use the stored credentials to make a secure connection an MQTT broker.
It will publish whatever data it receives on the configured subscribe topic to the configured publish topic.


Obtaining a certificate
=======================

The sample connects to ``krypton.soracom.io``, which requires an X.509 certificate.
This certificate is provided in the :file:`krypton_client/cert` folder.

To connect to other servers, you might need to provision a different certificate.
You can download a certificate for a given server using your web browser.
Alternatively, you can obtain it from a dedicated website like `SSL Labs`_.

Certificates come in different formats.
To provision the certificate to the nRF9160 DK, it must be in PEM format.
The PEM format looks like this::

  "-----BEGIN CERTIFICATE-----\n"
  "MIIFjTCCA3WgAwIBAgIRANOxciY0IzLc9AUoUSrsnGowDQYJKoZIhvcNAQELBQAw\n"
  "TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n"
  "cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTYxMDA2MTU0MzU1\n"
  "WhcNMjExMDA2MTU0MzU1WjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\n"
  "RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDMwggEi\n"
  "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc0wzwWuUuR7dyXTeDs2hjMOrX\n"
  "NSYZJeG9vjXxcJIvt7hLQQWrqZ41CFjssSrEaIcLo+N15Obzp2JxunmBYB/XkZqf\n"
  "89B4Z3HIaQ6Vkc/+5pnpYDxIzH7KTXcSJJ1HG1rrueweNwAcnKx7pwXqzkrrvUHl\n"
  "Npi5y/1tPJZo3yMqQpAMhnRnyH+lmrhSYRQTP2XpgofL2/oOVvaGifOFP5eGr7Dc\n"
  "Gu9rDZUWfcQroGWymQQ2dYBrrErzG5BJeC+ilk8qICUpBMZ0wNAxzY8xOJUWuqgz\n"
  "uEPxsR/DMH+ieTETPS02+OP88jNquTkxxa/EjQ0dZBYzqvqEKbbUC8DYfcOTAgMB\n"
  "AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU\n"
  "BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB\n"
  "FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBSo\n"
  "SmpjBH3duubRObemRWXv86jsoTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js\n"
  "LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF\n"
  "BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG\n"
  "AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD\n"
  "VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB\n"
  "ABnPdSA0LTqmRf/Q1eaM2jLonG4bQdEnqOJQ8nCqxOeTRrToEKtwT++36gTSlBGx\n"
  "A/5dut82jJQ2jxN8RI8L9QFXrWi4xXnA2EqA10yjHiR6H9cj6MFiOnb5In1eWsRM\n"
  "UM2v3e9tNsCAgBukPHAg1lQh07rvFKm/Bz9BCjaxorALINUfZ9DD64j2igLIxle2\n"
  "DPxW8dI/F2loHMjXZjqG8RkqZUdoxtID5+90FgsGIfkMpqgRS05f4zPbCEHqCXl1\n"
  "eO5HyELTgcVlLXXQDgAWnRzut1hFJeczY1tjQQno6f6s+nMydLN26WuU4s3UYvOu\n"
  "OsUxRlJu7TSRHqDC3lSE5XggVkzdaPkuKGQbGpny+01/47hfXXNB7HntWNZ6N2Vw\n"
  "p7G6OfY+YQrZwIaQmhrIqJZuigsrbe3W+gdn5ykE9+Ky0VgVUsfxo52mwFYs1JKY\n"
  "2PGDuWx8M6DlS6qQkvHaRUo0FMd8TsSlbF0/v965qGFKhSDeQoMpYnwcmQilRh/0\n"
  "ayLThlHLN81gSkJjVrPI0Y8xCVPB4twb1PFUd2fPM3sA1tJ83sZ5v8vgFv2yofKR\n"
  "PB0t6JzUA81mSqM3kxl5e+IZwhYAyO0OTg3/fs8HqGTNKd9BqoUwSRBzp06JMg5b\n"
  "rUCGwbCUDI0mxadJ3Bz4WxR6fyNpBK2yAinWEsikxqEt\n"
  "-----END CERTIFICATE-----\n"

Note the ``\n`` at the end of each line.

See the comprehensive `tutorial on SSL.com`_ for instructions on how to convert between different certificate formats and encodings.


Requirements
************

* The following development board:

  * |nRF9160DK|

* .. include:: /includes/spm.txt


Building and running
********************

.. |sample path| replace:: :file:`samples/nrf9160/krypton_client`

.. include:: /includes/build_and_run_nrf9160.txt

Setup
=======
* Add custom configurations in prj.conf including the Publish and Subscribe topics for the application. 
* Change CONFIG_REWRITE_EXISTING_CERT in main.c to true if you would like to application to request and flash new certificates
each time it runs. Leave false to skip certificate provisioning if certs already exist in the security tag.

Testing
=======

After programming the sample to your board, test it by performing the following steps:

1. Connect the USB cable and power on or reset your nRF9160 DK.
2. Open a terminal emulator and observe that the sample starts, provisions certificates, 
  connects to the LTE network and to krypton.soracom.io, and then downloads all certificates.
3. Observe that the modem goes into an offline state and stores the downloaded credentials.
4. Observe the modem comes back online after storing credentials.
5. Observe that the kit connects to the configured MQTT broker after it gets LTE connection.
   Now the kit is ready to echo whatever data is sent to it on the configured subscribe topic (``MQTT_SUB_TOPIC``).
6. Use an MQTT client like the [AWS IoT MQTT Client](https://docs.aws.amazon.com/iot/latest/developerguide/view-mqtt-messages.html) or mosquitto to subscribe to and publish data to the broker.
   Observe that the kit publishes all data that you publish to ``MQTT_SUB_TOPIC`` on ``MQTT_PUB_TOPIC``.

Sample Output
=============

The sample shows the following output:

.. code-block:: console

  Soracom Krypton client sample started
  Provisioning certificate
  Waiting for network.. OK
  Downloading certificates from Krypton.
  Requesting private key...
  Connecting to krypton.soracom.io
  Sent 182 bytes
  Received 2116 bytes
  Requesting public certificate...
  Connecting to krypton.soracom.io
  Sent 183 bytes
  Received 1413 bytes
  Requesting Root CA certificate...
  Connecting to krypton.soracom.io
  Sent 120 bytes
  Received 1381 bytes
  Finished downloading certificate.
  Turning modem to offline
  Storing private key...
  Storing public key...
  Storing Root CA...
  Credentials Stored. Bringing modem online.
  OK
  Network Status: 2
  Using certs to connect to AWS IoT using MQTT
  IPv4 Address found <IP_ADDRESS>
  [mqtt_evt_handler:666] MQTT client connected!
  Subscribing to: /my/subscribe/topic len 19
  [mqtt_evt_handler:716] SUBACK packet id: 1234
  [mqtt_evt_handler:721] default: 9
  [mqtt_evt_handler:721] default: 9
  [mqtt_evt_handler:721] default: 9

Troubleshooting
===============

After provisioning certificates, the board may take time to return to an online state. If it errors out with a message that it couldn't connect to 
the LTE network, increase the sleep time after setting the modem back to normal state. 

Dependencies
************

This sample uses the following libraries:

From |NCS|
  * :ref:`at_cmd_readme`
  * :ref:`at_notif_readme`
  * :ref:`modem_key_mgmt`
  * ``lib/lte_link_control``

From nrfxlib
  * :ref:`nrfxlib:bsdlib`

From Zephyr
* :ref:`MQTT <zephyr:networking_api>`

In addition, it uses the following samples:

From |NCS|
  * :ref:`secure_partition_manager`

References
**********

See the following page for information about how to enable Transport Security Layer in the Simple MQTT sample:

    * `Enabling and testing TLS in mqtt_simple`_