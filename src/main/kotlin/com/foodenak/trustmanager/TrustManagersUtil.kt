@file:JvmName("TrustManagersUtil")

package com.foodenak.trustmanager

import java.security.KeyStore
import javax.net.ssl.TrustManager

@Suppress("unused") fun create(keyStore: KeyStore): TrustManager = CustomTrustManagers(keyStore)