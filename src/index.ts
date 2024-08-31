import {
  getPublicKey,
  nip04,
  SimplePool,
  finalizeEvent,
  verifyEvent,
  type EventTemplate,
} from "nostr-tools";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { hexToBytes } from "@noble/hashes/utils";
import {
  EncryptedDirectMessage,
  EncryptedDirectMessages,
  Metadata,
  RelayList,
} from "nostr-tools/kinds";
import { npubEncode } from "nostr-tools/nip19";
import type { SubCloser } from "nostr-tools/abstract-pool";

import LitJsSdk, { encryptString } from "@lit-protocol/lit-node-client-nodejs";
import { LIT_RPC, LitNetwork } from "@lit-protocol/constants";
import {
  createSiweMessageWithRecaps,
  generateAuthSig,
  LitAbility,
  LitActionResource,
} from "@lit-protocol/auth-helpers";
import { EthWalletProvider } from "@lit-protocol/lit-auth-client";
import { ethers } from "ethers";

const PRIVATE_KEY = process.env.PRIVATE_KEY;
const GENERATE_WALLET_IPFS_ID = process.env.LIT_GENERATE_ADDRESS_IPFS;
const PKP_PUBLIC_KEY = process.env.PKP_PUBLIC_KEY;

export interface PartialRelayListEvent extends EventTemplate {
  kind: typeof RelayList;
  tags: (["r", string] | ["r", string, "read" | "write"])[];
  content: "";
}

export async function startService({
  pool = new SimplePool(),
  seedKey = process.env.SEED_KEY,
  keyIndex = process.env.KEY_INDEX ? parseInt(process.env.KEY_INDEX) : 0,
}: {
  pool?: SimplePool;
  seedKey?: string;
  keyIndex?: number;
} = {}) {
  if (!seedKey) throw new Error("No seed key provided");
  const [nostrSeckey, nostrPubkey] = getAppKeyPair(seedKey, keyIndex);

  if (!nostrSeckey || !nostrPubkey)
    throw new Error("No nostr key pair generated");

  console.info("npub:", npubEncode(nostrPubkey));

  const relays = await loadNostrRelayList(nostrPubkey, nostrSeckey, { pool });

  console.info("nostrRelays:", relays);

  const profileMetadata = await pool.get(Object.keys(relays), {
    kinds: [Metadata],
    authors: [nostrPubkey],
  });
  if (!profileMetadata) {
    const metadataEvent: EventTemplate = {
      kind: Metadata,
      content: JSON.stringify({
        name: "Test-Relay-Bot",
        about: "Test-Relay-Bot is a bot for receive a payload from Test-Bot",
        nip05: "Test-Relay-Bot",
        lud06: "Test-Relay-Bot",
      }),
      tags: [
        ["p", nostrPubkey],
        ["d", "Test-Relay-Bot"],
      ],
      created_at: Math.floor(Date.now() / 1000),
    };
    await Promise.all(
      pool.publish(
        Object.keys(relays),
        finalizeEvent(metadataEvent, nostrSeckey)
      )
    );
    console.info("Profile Metadata published");
  } else {
    console.info("Profile Metadata exists", profileMetadata);
  }

  const subDmOnly = pool.subscribeMany(
    Object.keys(relays),
    [
      {
        kinds: [EncryptedDirectMessage], // DMs
        "#p": [nostrPubkey], // only want DMs for us
        since: Math.floor(Date.now() / 1000), // only want DMs since now
      },
    ],
    {
      async onevent(event) {
        console.info("Received DM:", event);
        if (verifyEvent(event)) {
          const payload = await nip04.decrypt(
            nostrSeckey,
            event.pubkey,
            event.content
          );
          console.info("Payload:", payload);
          // JSON.parse(payload)
          if (payload.toLowerCase().includes("register")) {
            // TODO: Call Lit Action
            // litsdk.call({ event })
            await generateUserWallet();
          }
        }
      },
      // oneose() {
      //   subDmOnly.close();
      // },
    }
  );

  return {
    pool,
    subs: [subDmOnly],
  };
}

export function stopService({
  pool,
  subs,
}: {
  pool: SimplePool;
  subs: SubCloser[];
}) {
  subs.forEach((sub) => sub.close());
  return pool.destroy();
}

export function numToBytes(num: number, bytes: number) {
  const b = new ArrayBuffer(bytes);
  const v = new DataView(b);
  v.setUint32(0, num);
  return new Uint8Array(b);
}

export function getAppKeyPair(initialKey: string, keyIndex: number) {
  if (!initialKey) return [];

  // Derive the Nostr Key from Metadata Key
  const dkLen = 32; // HKDF output key length
  const salt = numToBytes(keyIndex, dkLen); // HKDF salt is set to a zero-filled byte sequence equal to the hash's output length
  const info = "nostr"; // HKDF info is set to an application-specific byte sequence distinct from other uses of HKDF in the application
  const seckey = hkdf(sha256, hexToBytes(initialKey), salt, info, dkLen);

  const pubkey = getPublicKey(seckey);
  return [seckey, pubkey] as const;
}

export async function loadNostrRelayList(
  pubKey: string,
  secKey: Uint8Array,
  opts: {
    pool?: SimplePool;
    nostr_relays?: { [url: string]: { read: boolean; write: boolean } };
  } = {}
) {
  const { pool = new SimplePool(), nostr_relays = {} } = opts;

  // See: https://github.com/nostr-protocol/nips/blob/master/65.md#when-to-use-read-and-write
  const nostr_write_relays = Object.entries(nostr_relays)
    .filter(([_url, r]) => r.write)
    .map(([url, _r]) => url);
  if (!nostr_write_relays.length)
    nostr_write_relays.push("wss://relay.damus.io");

  const relay_list_note = await pool.get(nostr_write_relays, {
    kinds: [RelayList],
    authors: [pubKey],
  });
  if (relay_list_note && verifyEvent(relay_list_note)) {
    // Use existing relay list
    relay_list_note.tags
      .filter((tag) => tag[0] === "r")
      .forEach((tag) => {
        if (tag.length === 3) {
          const [, relay, typ] = tag;
          if (typ === "read") {
            nostr_relays[relay] = { read: true, write: false };
          } else if (typ === "write") {
            nostr_relays[relay] = { read: false, write: false };
          }
        } else if (tag.length === 2) {
          const [, relay] = tag;
          nostr_relays[relay] = { read: true, write: true };
        }
      });
  } else {
    // Write relay list
    const nostr_read_relays = Object.entries(nostr_relays)
      .filter(([_url, r]) => r.read)
      .map(([url, _r]) => url);
    if (!nostr_read_relays.length)
      nostr_read_relays.push("wss://relay.damus.io");

    const event: PartialRelayListEvent = {
      kind: RelayList,
      content: "",
      tags: [
        ...nostr_write_relays.map((relay) =>
          nostr_read_relays.includes(relay)
            ? (["r", relay] as ["r", string])
            : (["r", relay, "write"] as ["r", string, "write"])
        ),
        ...nostr_read_relays
          .filter((relay) => !nostr_write_relays.includes(relay))
          .map((relay) => ["r", relay, "read"] as ["r", string, "read"]),
      ],
      created_at: Math.floor(Date.now() / 1000),
    };

    await Promise.all(
      pool.publish(nostr_write_relays, finalizeEvent(event, secKey))
    );

    nostr_read_relays.forEach((relay) => {
      nostr_relays[relay] = nostr_write_relays.includes(relay)
        ? { read: true, write: true }
        : { read: true, write: false };
    });
  }

  return nostr_relays;
}

export async function generateUserWallet() {
  if (!PRIVATE_KEY || !GENERATE_WALLET_IPFS_ID || !PKP_PUBLIC_KEY) return;

  const ethersSigner = new ethers.Wallet(
    PRIVATE_KEY,
    new ethers.providers.JsonRpcProvider(LIT_RPC.CHRONICLE_YELLOWSTONE)
  );

  console.log("🔄 Connecting to Lit network...");
  const litNodeClient = new LitJsSdk.LitNodeClientNodeJs({
    alertWhenUnauthorized: false,
    litNetwork: LitNetwork.DatilDev,
    debug: false,
  });

  await litNodeClient.connect();
  console.log("✅ Connected to Lit network");

  const sessionSigs = await litNodeClient.getSessionSigs({
    chain: "ethereum",
    expiration: new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(), // 24 hours
    resourceAbilityRequests: [
      {
        resource: new LitActionResource("*"),
        ability: LitAbility.LitActionExecution,
      },
    ],
    authNeededCallback: async ({
      resourceAbilityRequests,
      expiration,
      uri,
    }) => {
      const toSign = await createSiweMessageWithRecaps({
        uri: uri!,
        expiration: expiration!,
        resources: resourceAbilityRequests!,
        walletAddress: ethersSigner.address,
        nonce: await litNodeClient.getLatestBlockhash(),
        litNodeClient,
      });

      return await generateAuthSig({
        signer: ethersSigner,
        toSign,
      });
    },
  });

  const generateWallet = await litNodeClient.executeJs({
    sessionSigs,
    ipfsId: GENERATE_WALLET_IPFS_ID,
  });

  console.log(generateWallet.response);

  // console.log("🔄 Getting PKP Session Sigs...");
  // const pkpSessionSigs = await litNodeClient.getPkpSessionSigs({
  //   pkpPublicKey: PKP_PUBLIC_KEY,
  //   authMethods: [
  //     await EthWalletProvider.authenticate({
  //       signer: ethersSigner,
  //       litNodeClient: LitNodeClient,
  //       expiration: new Date(Date.now() + 1000 * 60 * 10).toISOString(), // 10 minutes
  //     }),
  //   ],
  //   resourceAbilityRequests: [
  //     {
  //       resource: new LitActionResource("*"),
  //       ability: LitAbility.LitActionExecution,
  //     },
  //   ],
  //   expiration: new Date(Date.now() + 1000 * 60 * 10).toISOString(), // 10 minutes
  // });
  // console.log("✅ Got PKP Session Sigs");

  // console.log("🔄 Encrypting private key...");
  //   const { ciphertext, dataToEncryptHash } = await encryptString(
  //     {
  //       accessControlConditions: [
  //         {
  //           contractAddress: "",
  //           standardContractType: "",
  //           chain: "ethereum",
  //           method: "",
  //           parameters: [":userAddress"],
  //           returnValueTest: {
  //             comparator: "=",
  //             value: ethersSigner,
  //           },
  //         },
  //       ],
  //       dataToEncrypt: privateKey,
  //     },
  //     litNodeClient
  //   );
  //   console.log("✅ Encrypted private key");
}
