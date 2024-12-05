import * as bip39 from 'bip39';
import { PublicKey } from './publicKey.js';
import { generateKeypair, getPublicKey, fromMnemonic } from './utils/ed25519.js';

/**
 * A Keypair class for managing public and private keys.
 */
export class Keypair {
  /**
   * Internal storage of the Ed25519 keypair
   * @private
   */
  _keypair;
  _mnemonic; // To store the mnemonic used for generation

  /**
   * Create a new keypair instance.
   * If no mnemonic is provided, generate a random mnemonic and keypair.
   * If a mnemonic is provided, generate a keypair from it.
   *
   * @param {string} [mnemonic] An optional mnemonic to generate the keypair.
   */
  constructor(mnemonic) {
    if (mnemonic) {
      // Generate keypair from mnemonic
      if (!bip39.validateMnemonic(mnemonic)) {
        throw new Error('Invalid mnemonic');
      }
      this._keypair = fromMnemonic(mnemonic); // Use utility function
      this._mnemonic = mnemonic;
    } else {
      // Generate a random mnemonic and derive keypair
      this._mnemonic = bip39.generateMnemonic();
      this._keypair = fromMnemonic(this._mnemonic);
    }
  }

  /**
   * Generate a new random keypair.
   *
   * @returns {Keypair} A new Keypair instance with generated public and secret keys.
   */
  static generate() {
    const keypair = generateKeypair(); // Use utility function
    return new KeypairFromGenerated(keypair);
  }

  /**
   * Generate a keypair from a BIP39 mnemonic.
   *
   * @param {string} mnemonic The BIP39 mnemonic phrase.
   * @returns {Keypair} The keypair instance generated from the mnemonic.
   */
  static fromMnemonic(mnemonic) {
    if (!bip39.validateMnemonic(mnemonic)) {
      throw new Error('Invalid mnemonic');
    }
    const keypair = fromMnemonic(mnemonic); // Use utility function
    const instance = new Keypair();
    instance._keypair = keypair;
    instance._mnemonic = mnemonic;
    return instance;
  }

  /**
   * Get the public key associated with this keypair.
   *
   * @returns {PublicKey} The public key.
   */
  get publicKey() {
    return new PublicKey(this._keypair.publicKey);
  }

  /**
   * Get the secret key associated with this keypair.
   *
   * @returns {Uint8Array} The secret key as a Uint8Array.
   */
  get secretKey() {
    return new Uint8Array(this._keypair.secretKey);
  }

  /**
   * Get the mnemonic used to generate this keypair (if available).
   *
   * @returns {string} The mnemonic (if generated from one), or undefined.
   */
  getMnemonic() {
    return this._mnemonic;
  }

  /**
   * Recreate the keypair from the stored mnemonic.
   *
   * @returns {Keypair} A new Keypair instance recovered from the mnemonic.
   */
  recoverFromMnemonic() {
    if (!this._mnemonic) {
      throw new Error('No mnemonic available to recover from');
    }
    return Keypair.fromMnemonic(this._mnemonic);
  }

  /**
   * Generate a keypair from a secret key (64-byte).
   *
   * @param {Uint8Array} secretKey The 64-byte secret key.
   * @param {Object} [options] Options for validation.
   * @returns {Keypair} The keypair generated from the secret key.
   */
  static fromSecretKey(secretKey, options = {}) {
    if (secretKey.byteLength !== 64) {
      throw new Error('Invalid secret key size');
    }

    const publicKey = secretKey.slice(32, 64);

    if (!options.skipValidation) {
      const privateKey = secretKey.slice(0, 32);
      const computedPublicKey = getPublicKey(privateKey); // Use utility function

      for (let i = 0; i < 32; i++) {
        if (publicKey[i] !== computedPublicKey[i]) {
          throw new Error('Provided secretKey is invalid');
        }
      }
    }

    return new KeypairFromGenerated({ publicKey, secretKey });
  }
}

/**
 * A helper class for generating and managing keypairs from generated keys.
 */
class KeypairFromGenerated extends Keypair {
  constructor(keypair) {
    super();
    this._keypair = keypair;
  }
}

// Export the Keypair class
export default Keypair;
