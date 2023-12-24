const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(express.json());

const accountMap = new Map();

async function deleteWorker(Authorization, accountId, scriptName) {
  const res = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${scriptName}`,
    {
      headers: {
        Authorization,
        'Content-Type': `application/json`,
      },
      method: 'DELETE',
    }
  ).then((res) => res.json());
}

async function getWorkerList(Authorization, accountId) {
  const res = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts`,
    {
      headers: {
        Authorization,
        'Content-Type': `application/json`,
      },
    }
  ).then((res) => res.json());

  const { result } = res;
  return result;
}

async function getAccountId(Authorization) {
  const res = await fetch(
    `https://api.cloudflare.com/client/v4/memberships?no-permissions=1&status=accepted`,
    {
      headers: {
        Authorization,
        'Content-Type': `application/json`,
      },
    }
  ).then((res) => res.json());
  console.log(res);
  const {
    result: [
      {
        account: { id },
      },
    ],
  } = res;
  console.log('获取到accountId: ', id);
  return id;
}

async function openSubDomain(Authorization, accountId, scriptName) {
  const res = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/services/${scriptName}/environments/production/subdomain`,
    {
      method: 'POST',
      headers: {
        Authorization,
        'Content-Type': `application/json`,
      },
      body: JSON.stringify({ enabled: true }),
    }
  ).then((res) => res.json());
  console.log(res);
}

async function createWorker(
  Authorization,
  accountId,
  scriptName,
  uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4'
) {
  const res = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/services/${scriptName}/environments/production`,
    {
      headers: {
        Authorization,
        'content-type':
          'multipart/form-data; boundary=----WebKitFormBoundaryYGhrdCoV2RZeMINp',
      },
      // referrer: 'https://dash.cloudflare.com/',
      // referrerPolicy: 'origin',
      body:
        '------WebKitFormBoundaryYGhrdCoV2RZeMINp\r\nContent-Disposition: form-data; name="worker.js"; filename="worker.js"\r\nContent-Type: application/javascript+module\r\n\r\n// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2023-06-22 15:20:02 UTC<!--GAMFC-END-->.\n// @ts-ignore\nimport { connect } from \'cloudflare:sockets\';\n\n// How to generate your own UUID:\n// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"\nlet userID = \'' +
        uuid +
        "';\n\nconst proxyIPs = ['cdn-all.xn--b6gac.eu.org', 'cdn.xn--b6gac.eu.org', 'cdn-b100.xn--b6gac.eu.org', 'edgetunnel.anycast.eu.org', 'cdn.anycast.eu.org'];\nlet proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];\n\nlet dohURL = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg='; // https://cloudflare-dns.com/dns-query or https://dns.google/dns-query\n\n// v2board api environment variables\nlet nodeId = ''; // 1\n\nlet apiToken = ''; //abcdefghijklmnopqrstuvwxyz123456\n\nlet apiHost = ''; // api.v2board.com\n\nif (!isValidUUID(userID)) {\n    throw new Error('uuid is not valid');\n}\n\nexport default {\n    /**\n     * @param {import(\"@cloudflare/workers-types\").Request} request\n     * @param {{UUID: string, PROXYIP: string, DNS_RESOLVER_URL: string, NODE_ID: int, API_HOST: string, API_TOKEN: string}} env\n     * @param {import(\"@cloudflare/workers-types\").ExecutionContext} ctx\n     * @returns {Promise<Response>}\n     */\n    async fetch(request, env, ctx) {\n        try {\n            userID = env.UUID || userID;\n            proxyIP = env.PROXYIP || proxyIP;\n            dohURL = env.DNS_RESOLVER_URL || dohURL;\n            nodeId = env.NODE_ID || nodeId;\n            apiToken = env.API_TOKEN || apiToken;\n            apiHost = env.API_HOST || apiHost;\n            const upgradeHeader = request.headers.get('Upgrade');\n            if (!upgradeHeader || upgradeHeader !== 'websocket') {\n                const url = new URL(request.url);\n                switch (url.pathname) {\n                    case '/cf':\n                        return new Response(JSON.stringify(request.cf, null, 4), {\n                            status: 200,\n                            headers: {\n                                \"Content-Type\": \"application/json;charset=utf-8\",\n                            },\n                        });\n                    case '/connect': // for test connect to cf socket\n                        const [hostname, port] = ['cloudflare.com', '80'];\n                        console.log(`Connecting to ${hostname}:${port}...`);\n\n                        try {\n                            const socket = await connect({\n                                hostname: hostname,\n                                port: parseInt(port, 10),\n                            });\n\n                            const writer = socket.writable.getWriter();\n\n                            try {\n                                await writer.write(new TextEncoder().encode('GET / HTTP/1.1\\r\\nHost: ' + hostname + '\\r\\n\\r\\n'));\n                            } catch (writeError) {\n                                writer.releaseLock();\n                                await socket.close();\n                                return new Response(writeError.message, { status: 500 });\n                            }\n\n                            writer.releaseLock();\n\n                            const reader = socket.readable.getReader();\n                            let value;\n\n                            try {\n                                const result = await reader.read();\n                                value = result.value;\n                            } catch (readError) {\n                                await reader.releaseLock();\n                                await socket.close();\n                                return new Response(readError.message, { status: 500 });\n                            }\n\n                            await reader.releaseLock();\n                            await socket.close();\n\n                            return new Response(new TextDecoder().decode(value), { status: 200 });\n                        } catch (connectError) {\n                            return new Response(connectError.message, { status: 500 });\n                        }\n                    case `/${userID}`: {\n                        const vlessConfig = getVLESSConfig(userID, request.headers.get('Host'));\n                        return new Response(`${vlessConfig}`, {\n                            status: 200,\n                            headers: {\n                                \"Content-Type\": \"text/plain;charset=utf-8\",\n                            }\n                        });\n                    }\n                    default:\n                        // return new Response('Not found', { status: 404 });\n                        // For any other path, reverse proxy to 'maimai.sega.jp' and return the original response\n                        url.hostname = 'maimai.sega.jp';\n                        url.protocol = 'https:';\n                        request = new Request(url, request);\n                        return await fetch(request);\n                }\n            } else {\n                return await vlessOverWSHandler(request);\n            }\n        } catch (err) {\n\t\t\t/** @type {Error} */ let e = err;\n            return new Response(e.toString());\n        }\n    },\n};\n\n\n\n\n/**\n * \n * @param {import(\"@cloudflare/workers-types\").Request} request\n */\nasync function vlessOverWSHandler(request) {\n\n    /** @type {import(\"@cloudflare/workers-types\").WebSocket[]} */\n    // @ts-ignore\n    const webSocketPair = new WebSocketPair();\n    const [client, webSocket] = Object.values(webSocketPair);\n\n    webSocket.accept();\n\n    let address = '';\n    let portWithRandomLog = '';\n    const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {\n        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');\n    };\n    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';\n\n    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);\n\n    /** @type {{ value: import(\"@cloudflare/workers-types\").Socket | null}}*/\n    let remoteSocketWapper = {\n        value: null,\n    };\n    let udpStreamWrite = null;\n    let isDns = false;\n\n    // ws --> remote\n    readableWebSocketStream.pipeTo(new WritableStream({\n        async write(chunk, controller) {\n            if (isDns && udpStreamWrite) {\n                return udpStreamWrite(chunk);\n            }\n            if (remoteSocketWapper.value) {\n                const writer = remoteSocketWapper.value.writable.getWriter()\n                await writer.write(chunk);\n                writer.releaseLock();\n                return;\n            }\n\n            const {\n                hasError,\n                message,\n                portRemote = 443,\n                addressRemote = '',\n                rawDataIndex,\n                vlessVersion = new Uint8Array([0, 0]),\n                isUDP,\n            } = await processVlessHeader(chunk, userID);\n            address = addressRemote;\n            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '\n                } `;\n            if (hasError) {\n                // controller.error(message);\n                throw new Error(message); // cf seems has bug, controller.error will not end stream\n                // webSocket.close(1000, message);\n                return;\n            }\n            // if UDP but port not DNS port, close it\n            if (isUDP) {\n                if (portRemote === 53) {\n                    isDns = true;\n                } else {\n                    // controller.error('UDP proxy only enable for DNS which is port 53');\n                    throw new Error('UDP proxy only enable for DNS which is port 53'); // cf seems has bug, controller.error will not end stream\n                    return;\n                }\n            }\n            // [\"version\", \"附加信息长度 N\"]\n            const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);\n            const rawClientData = chunk.slice(rawDataIndex);\n\n            // TODO: support udp here when cf runtime has udp support\n            if (isDns) {\n                const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);\n                udpStreamWrite = write;\n                udpStreamWrite(rawClientData);\n                return;\n            }\n            handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);\n        },\n        close() {\n            log(`readableWebSocketStream is close`);\n        },\n        abort(reason) {\n            log(`readableWebSocketStream is abort`, JSON.stringify(reason));\n        },\n    })).catch((err) => {\n        log('readableWebSocketStream pipeTo error', err);\n    });\n\n    return new Response(null, {\n        status: 101,\n        // @ts-ignore\n        webSocket: client,\n    });\n}\n\nlet apiResponseCache = null;\nlet cacheTimeout = null;\n\n/**\n * Fetches the API response from the server and caches it for future use.\n * @returns {Promise<object|null>} A Promise that resolves to the API response object or null if there was an error.\n */\nasync function fetchApiResponse() {\n    const requestOptions = {\n        method: 'GET',\n        redirect: 'follow'\n    };\n\n    try {\n        const response = await fetch(`https://${apiHost}/api/v1/server/UniProxy/user?node_id=${nodeId}&node_type=v2ray&token=${apiToken}`, requestOptions);\n\n        if (!response.ok) {\n            console.error('Error: Network response was not ok');\n            return null;\n        }\n        const apiResponse = await response.json();\n        apiResponseCache = apiResponse;\n\n        // Refresh the cache every 5 minutes (300000 milliseconds)\n        if (cacheTimeout) {\n            clearTimeout(cacheTimeout);\n        }\n        cacheTimeout = setTimeout(() => fetchApiResponse(), 300000);\n\n        return apiResponse;\n    } catch (error) {\n        console.error('Error:', error);\n        return null;\n    }\n}\n\n/**\n * Returns the cached API response if it exists, otherwise fetches the API response from the server and caches it for future use.\n * @returns {Promise<object|null>} A Promise that resolves to the cached API response object or the fetched API response object, or null if there was an error.\n */\nasync function getApiResponse() {\n    if (!apiResponseCache) {\n        return await fetchApiResponse();\n    }\n    return apiResponseCache;\n}\n\n/**\n * Checks if a given UUID is present in the API response.\n * @param {string} targetUuid The UUID to search for.\n * @returns {Promise<boolean>} A Promise that resolves to true if the UUID is present in the API response, false otherwise.\n */\nasync function checkUuidInApiResponse(targetUuid) {\n    // Check if any of the environment variables are empty\n    if (!nodeId || !apiToken || !apiHost) {\n        return false;\n    }\n\n    try {\n        const apiResponse = await getApiResponse();\n        if (!apiResponse) {\n            return false;\n        }\n        const isUuidInResponse = apiResponse.users.some(user => user.uuid === targetUuid);\n        return isUuidInResponse;\n    } catch (error) {\n        console.error('Error:', error);\n        return false;\n    }\n}\n\n// Usage example:\n//   const targetUuid = \"65590e04-a94c-4c59-a1f2-571bce925aad\";\n//   checkUuidInApiResponse(targetUuid).then(result => console.log(result));\n\n/**\n * Handles outbound TCP connections.\n *\n * @param {any} remoteSocket \n * @param {string} addressRemote The remote address to connect to.\n * @param {number} portRemote The remote port to connect to.\n * @param {Uint8Array} rawClientData The raw client data to write.\n * @param {import(\"@cloudflare/workers-types\").WebSocket} webSocket The WebSocket to pass the remote socket to.\n * @param {Uint8Array} vlessResponseHeader The VLESS response header.\n * @param {function} log The logging function.\n * @returns {Promise<void>} The remote socket.\n */\nasync function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log,) {\n    async function connectAndWrite(address, port) {\n        /** @type {import(\"@cloudflare/workers-types\").Socket} */\n        const tcpSocket = connect({\n            hostname: address,\n            port: port,\n        });\n        remoteSocket.value = tcpSocket;\n        log(`connected to ${address}:${port}`);\n        const writer = tcpSocket.writable.getWriter();\n        await writer.write(rawClientData); // first write, nomal is tls client hello\n        writer.releaseLock();\n        return tcpSocket;\n    }\n\n    // if the cf connect tcp socket have no incoming data, we retry to redirect ip\n    async function retry() {\n        const tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote)\n        // no matter retry success or not, close websocket\n        tcpSocket.closed.catch(error => {\n            console.log('retry tcpSocket closed error', error);\n        }).finally(() => {\n            safeCloseWebSocket(webSocket);\n        })\n        remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);\n    }\n\n    const tcpSocket = await connectAndWrite(addressRemote, portRemote);\n\n    // when remoteSocket is ready, pass to websocket\n    // remote--> ws\n    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);\n}\n\n/**\n * \n * @param {import(\"@cloudflare/workers-types\").WebSocket} webSocketServer\n * @param {string} earlyDataHeader for ws 0rtt\n * @param {(info: string)=> void} log for ws 0rtt\n */\nfunction makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {\n    let readableStreamCancel = false;\n    const stream = new ReadableStream({\n        start(controller) {\n            webSocketServer.addEventListener('message', (event) => {\n                if (readableStreamCancel) {\n                    return;\n                }\n                const message = event.data;\n                controller.enqueue(message);\n            });\n\n            // The event means that the client closed the client -> server stream.\n            // However, the server -> client stream is still open until you call close() on the server side.\n            // The WebSocket protocol says that a separate close message must be sent in each direction to fully close the socket.\n            webSocketServer.addEventListener('close', () => {\n                // client send close, need close server\n                // if stream is cancel, skip controller.close\n                safeCloseWebSocket(webSocketServer);\n                if (readableStreamCancel) {\n                    return;\n                }\n                controller.close();\n            }\n            );\n            webSocketServer.addEventListener('error', (err) => {\n                log('webSocketServer has error');\n                controller.error(err);\n            }\n            );\n            // for ws 0rtt\n            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);\n            if (error) {\n                controller.error(error);\n            } else if (earlyData) {\n                controller.enqueue(earlyData);\n            }\n        },\n\n        pull(controller) {\n            // if ws can stop read if stream is full, we can implement backpressure\n            // https://streams.spec.whatwg.org/#example-rs-push-backpressure\n        },\n        cancel(reason) {\n            // 1. pipe WritableStream has error, this cancel will called, so ws handle server close into here\n            // 2. if readableStream is cancel, all controller.close/enqueue need skip,\n            // 3. but from testing controller.error still work even if readableStream is cancel\n            if (readableStreamCancel) {\n                return;\n            }\n            log(`ReadableStream was canceled, due to ${reason}`)\n            readableStreamCancel = true;\n            safeCloseWebSocket(webSocketServer);\n        }\n    });\n\n    return stream;\n\n}\n\n// https://xtls.github.io/development/protocols/vless.html\n// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw\n\n/**\n * \n * @param { ArrayBuffer} vlessBuffer \n * @param {string} userID \n * @returns \n */\nasync function processVlessHeader(\n    vlessBuffer,\n    userID\n) {\n    if (vlessBuffer.byteLength < 24) {\n        return {\n            hasError: true,\n            message: 'invalid data',\n        };\n    }\n    const version = new Uint8Array(vlessBuffer.slice(0, 1));\n    let isValidUser = false;\n    let isUDP = false;\n    const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));\n    const slicedBufferString = stringify(slicedBuffer);\n\n    const uuids = userID.includes(',') ? userID.split(\",\") : [userID];\n\n    const checkUuidInApi = await checkUuidInApiResponse(slicedBufferString);\n    isValidUser = uuids.some(userUuid => checkUuidInApi || slicedBufferString === userUuid.trim());\n\n    console.log(`checkUuidInApi: ${await checkUuidInApiResponse(slicedBufferString)}, userID: ${slicedBufferString}`);\n\n    if (!isValidUser) {\n        return {\n            hasError: true,\n            message: 'invalid user',\n        };\n    }\n\n    const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];\n    //skip opt for now\n\n    const command = new Uint8Array(\n        vlessBuffer.slice(18 + optLength, 18 + optLength + 1)\n    )[0];\n\n    // 0x01 TCP\n    // 0x02 UDP\n    // 0x03 MUX\n    if (command === 1) {\n    } else if (command === 2) {\n        isUDP = true;\n    } else {\n        return {\n            hasError: true,\n            message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,\n        };\n    }\n    const portIndex = 18 + optLength + 1;\n    const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);\n    // port is big-Endian in raw data etc 80 == 0x005d\n    const portRemote = new DataView(portBuffer).getUint16(0);\n\n    let addressIndex = portIndex + 2;\n    const addressBuffer = new Uint8Array(\n        vlessBuffer.slice(addressIndex, addressIndex + 1)\n    );\n\n    // 1--> ipv4  addressLength =4\n    // 2--> domain name addressLength=addressBuffer[1]\n    // 3--> ipv6  addressLength =16\n    const addressType = addressBuffer[0];\n    let addressLength = 0;\n    let addressValueIndex = addressIndex + 1;\n    let addressValue = '';\n    switch (addressType) {\n        case 1:\n            addressLength = 4;\n            addressValue = new Uint8Array(\n                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)\n            ).join('.');\n            break;\n        case 2:\n            addressLength = new Uint8Array(\n                vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)\n            )[0];\n            addressValueIndex += 1;\n            addressValue = new TextDecoder().decode(\n                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)\n            );\n            break;\n        case 3:\n            addressLength = 16;\n            const dataView = new DataView(\n                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)\n            );\n            // 2001:0db8:85a3:0000:0000:8a2e:0370:7334\n            const ipv6 = [];\n            for (let i = 0; i < 8; i++) {\n                ipv6.push(dataView.getUint16(i * 2).toString(16));\n            }\n            addressValue = ipv6.join(':');\n            // seems no need add [] for ipv6\n            break;\n        default:\n            return {\n                hasError: true,\n                message: `invild  addressType is ${addressType}`,\n            };\n    }\n    if (!addressValue) {\n        return {\n            hasError: true,\n            message: `addressValue is empty, addressType is ${addressType}`,\n        };\n    }\n\n    return {\n        hasError: false,\n        addressRemote: addressValue,\n        addressType,\n        portRemote,\n        rawDataIndex: addressValueIndex + addressLength,\n        vlessVersion: version,\n        isUDP,\n    };\n}\n\n\n/**\n * \n * @param {import(\"@cloudflare/workers-types\").Socket} remoteSocket \n * @param {import(\"@cloudflare/workers-types\").WebSocket} webSocket \n * @param {ArrayBuffer} vlessResponseHeader \n * @param {(() => Promise<void>) | null} retry\n * @param {*} log \n */\nasync function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {\n    // remote--> ws\n    let remoteChunkCount = 0;\n    let chunks = [];\n    /** @type {ArrayBuffer | null} */\n    let vlessHeader = vlessResponseHeader;\n    let hasIncomingData = false; // check if remoteSocket has incoming data\n    await remoteSocket.readable\n        .pipeTo(\n            new WritableStream({\n                start() {\n                },\n                /**\n                 * \n                 * @param {Uint8Array} chunk \n                 * @param {*} controller \n                 */\n                async write(chunk, controller) {\n                    hasIncomingData = true;\n                    // remoteChunkCount++;\n                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {\n                        controller.error(\n                            'webSocket.readyState is not open, maybe close'\n                        );\n                    }\n                    if (vlessHeader) {\n                        webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());\n                        vlessHeader = null;\n                    } else {\n                        // seems no need rate limit this, CF seems fix this??..\n                        // if (remoteChunkCount > 20000) {\n                        // \t// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M\n                        // \tawait delay(1);\n                        // }\n                        webSocket.send(chunk);\n                    }\n                },\n                close() {\n                    log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);\n                    // safeCloseWebSocket(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.\n                },\n                abort(reason) {\n                    console.error(`remoteConnection!.readable abort`, reason);\n                },\n            })\n        )\n        .catch((error) => {\n            console.error(\n                `remoteSocketToWS has exception `,\n                error.stack || error\n            );\n            safeCloseWebSocket(webSocket);\n        });\n\n    // seems is cf connect socket have error,\n    // 1. Socket.closed will have error\n    // 2. Socket.readable will be close without any data coming\n    if (hasIncomingData === false && retry) {\n        log(`retry`)\n        retry();\n    }\n}\n\n/**\n * \n * @param {string} base64Str \n * @returns \n */\nfunction base64ToArrayBuffer(base64Str) {\n    if (!base64Str) {\n        return { error: null };\n    }\n    try {\n        // go use modified Base64 for URL rfc4648 which js atob not support\n        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');\n        const decode = atob(base64Str);\n        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));\n        return { earlyData: arryBuffer.buffer, error: null };\n    } catch (error) {\n        return { error };\n    }\n}\n\n/**\n * This is not real UUID validation\n * @param {string} uuid \n */\nfunction isValidUUID(uuid) {\n    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;\n    return uuidRegex.test(uuid);\n}\n\nconst WS_READY_STATE_OPEN = 1;\nconst WS_READY_STATE_CLOSING = 2;\n/**\n * Normally, WebSocket will not has exceptions when close.\n * @param {import(\"@cloudflare/workers-types\").WebSocket} socket\n */\nfunction safeCloseWebSocket(socket) {\n    try {\n        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {\n            socket.close();\n        }\n    } catch (error) {\n        console.error('safeCloseWebSocket error', error);\n    }\n}\n\nconst byteToHex = [];\nfor (let i = 0; i < 256; ++i) {\n    byteToHex.push((i + 256).toString(16).slice(1));\n}\nfunction unsafeStringify(arr, offset = 0) {\n    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + \"-\" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + \"-\" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + \"-\" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + \"-\" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();\n}\nfunction stringify(arr, offset = 0) {\n    const uuid = unsafeStringify(arr, offset);\n    if (!isValidUUID(uuid)) {\n        throw TypeError(\"Stringified UUID is invalid\");\n    }\n    return uuid;\n}\n\n\n/**\n * \n * @param {import(\"@cloudflare/workers-types\").WebSocket} webSocket \n * @param {ArrayBuffer} vlessResponseHeader \n * @param {(string)=> void} log \n */\nasync function handleUDPOutBound(webSocket, vlessResponseHeader, log) {\n\n    let isVlessHeaderSent = false;\n    const transformStream = new TransformStream({\n        start(controller) {\n\n        },\n        transform(chunk, controller) {\n            // udp message 2 byte is the the length of udp data\n            // TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message\n            for (let index = 0; index < chunk.byteLength;) {\n                const lengthBuffer = chunk.slice(index, index + 2);\n                const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);\n                const udpData = new Uint8Array(\n                    chunk.slice(index + 2, index + 2 + udpPakcetLength)\n                );\n                index = index + 2 + udpPakcetLength;\n                controller.enqueue(udpData);\n            }\n        },\n        flush(controller) {\n        }\n    });\n\n    // only handle dns udp for now\n    transformStream.readable.pipeTo(new WritableStream({\n        async write(chunk) {\n            const resp = await fetch(dohURL, // dns server url\n                {\n                    method: 'POST',\n                    headers: {\n                        'content-type': 'application/dns-message',\n                    },\n                    body: chunk,\n                })\n            const dnsQueryResult = await resp.arrayBuffer();\n            const udpSize = dnsQueryResult.byteLength;\n            // console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));\n            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);\n            if (webSocket.readyState === WS_READY_STATE_OPEN) {\n                log(`doh success and dns message length is ${udpSize}`);\n                if (isVlessHeaderSent) {\n                    webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());\n                } else {\n                    webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());\n                    isVlessHeaderSent = true;\n                }\n            }\n        }\n    })).catch((error) => {\n        log('dns udp has error' + error)\n    });\n\n    const writer = transformStream.writable.getWriter();\n\n    return {\n        /**\n         * \n         * @param {Uint8Array} chunk \n         */\n        write(chunk) {\n            writer.write(chunk);\n        }\n    };\n}\n\n/**\n * \n * @param {string} userID \n * @param {string | null} hostName\n * \n * \n * @returns {string}\n */\nfunction getVLESSConfig(userID, hostName) {\n    const vlessLink = `vless://${userID}@${hostName}:80?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${hostName}`\n    const vlessTlsLink = `vless://${userID}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${hostName}`\n    return `\n下面是非 TLS 端口的节点信息及分享链接，可使用 CF 支持的非 TLS 端口：\n\n地址：${hostName} 或 CF 优选 IP\n端口：80 或 CF 支持的非 TLS 端口\nUUID：${userID}\n传输：ws\n伪装域名：${hostName}\n路径：/?ed=2048\n\n${vlessLink}\n\n下面是 TLS 端口的节点信息及分享链接，可使用 CF 支持的 TLS 端口：\n\n地址：${hostName} 或 CF 优选 IP\n端口：443 或 CF 支持的 TLS 端口\nUUID：${userID}\n传输：ws\n传输层安全：TLS\n伪装域名：${hostName}\n路径：/?ed=2048\nSNI 域名：${hostName}\n\n${vlessTlsLink}\n\n提示：如使用 workers.dev 域名，则无法使用 TLS 端口\n---------------------------------------------------------------\n更多教程，请关注：小御坂的破站\n`;\n}\r\n------WebKitFormBoundaryYGhrdCoV2RZeMINp\r\nContent-Disposition: form-data; name=\"metadata\"; filename=\"blob\"\r\nContent-Type: application/json\r\n\r\n{\"compatibility_date\":\"2023-12-23\",\"bindings\":[],\"main_module\":\"worker.js\"}\r\n------WebKitFormBoundaryYGhrdCoV2RZeMINp--\r\n",
      method: 'PUT',
      // mode: 'cors',
      // credentials: 'include',
    }
  ).then((res) => res.json());

  console.log(res);
}

app.get('/', (_, res) => {
  res.send('Hello World!');
});

app.use(async (req, res, next) => {
  const token = req.query.token || req.body.token;

  if (!token) {
    res.json({
      msg: 'token is null',
    });
  }

  req.Authorization = `Bearer ${token}`;

  if (!accountMap.has(token)) {
    const accountId = await getAccountId(req.Authorization);
    accountMap.set(token, accountId);
    req.accountId = accountId;
  } else {
    req.accountId = accountMap.get(token);
  }

  next();
});

app.post('/list', async (req, res) => {
  const list = await getWorkerList(req.Authorization, req.accountId);
  res.json(list);
});

app.post('/create', async (req, res) => {
  try {
    const scriptName = req.body.scriptName || 'a';
    const uuid = req.body.uuid;
    await createWorker(req.Authorization, req.accountId, scriptName, uuid);
    await openSubDomain(req.Authorization, req.accountId, scriptName);

    res.json({ msg: 'ok' });
  } catch (error) {
    console.log(error);
    res.json({ msg: 'error' + error?.errmsg });
  }
});

app.post('/del', async (req, res) => {
  if (req.body.scriptName) {
    await deleteWorker(req.Authorization, req.accountId, req.body.scriptName);
    res.json({
      msg: 'ok',
    });
  } else {
    res.json({
      msg: 'scriptName is null',
    });
  }
});

app.post('/delAll', async (req, res) => {
  if (req.body.sure) {
    const list = await getWorkerList(req.Authorization, req.accountId);
    list.forEach((i) => deleteWorker(req.Authorization, req.accountId, i.id));
    res.json({
      msg: 'ok',
    });
  } else {
    res.json({
      msg: 'sure is null',
    });
  }
});

app.listen(3000);
