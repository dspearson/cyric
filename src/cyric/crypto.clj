(ns cyric.crypto
  (:require
   [clojure.java.io :as io]
   [clojure.java.jdbc :refer :all]
   [ring.adapter.jetty :as jetty]
   [crypto.random :refer [hex]]
   [buddy.hashers :as hashers]
   [buddy.core.hash :as hash]
   [caesium.crypto.secretbox :as sb]
   [caesium.crypto.box :as b]
   [caesium.byte-bufs :as bu]
   [caesium.util :as u]
   [clj-time.core :as t]
   [clj-time.format :as f]
   [clj-time.coerce :as c]
   [byte-streams :as bs]
   [cyric.db :refer :all]
   [buddy.core.codecs :refer :all]
   [clojure.data.codec.base64 :as b64]
   [buddy.core.nonce :as nonce]
   [cyric.util :refer :all]
   [clojure.data.json :as json]))

(def master-public-key (:public (first (query db ["SELECT public FROM key_bundles WHERE type = 'identity' AND name = 'master'"]))))
(def master-secret-key (:secret (first (query db ["SELECT secret FROM key_bundles WHERE type = 'identity' AND name = 'master'"]))))

(defn hashcash-init!
  "create an initial hashcash token"
  [signed-by difficulty]
  (array-map :epoch (c/to-long (t/now)) :difficulty difficulty :signed-by signed-by :nonce 0 :cash (crypto.random/base64 12)))

(defn valid-hashcash?
  "check if our hashcash is valid"
  [cash]
  (let [difficulty (parse-int (subs cash 2 3))]
    (if (= (subs (bytes->hex (hash/sha256 (str cash))) 0 difficulty) (apply str (repeat difficulty "0")))
      true
      false)))

(defn hashcash-iter
  "try another hashcash value"
  [hash]
  (array-map :epoch (:epoch hash) :difficulty (:difficulty hash) :signed-by (:signed-by hash) :nonce (+ 1 (:nonce hash)) :cash (:cash hash)))

(def hashcash-difficulty 4)

(defn hashcash
  "hashcash implementation"
  [& hash]
  (cond
    (nil? hash)
    (recur (hashcash-init! "nobody" hashcash-difficulty))

    (seq? hash)
    (recur (first hash))

    (and (nil? hash) (nil? (first hash)))
    (recur (hashcash-init! "nobody" hashcash-difficulty))

    :else
    (let [cash (str "1:"
                    (:difficulty hash) ":"
                    (:epoch hash) ":"
                    (:signed-by hash) "::"
                    (:cash hash) ":"
                    (bytes->str (b64/encode (str->bytes (str (:nonce hash))))))]
      (if (valid-hashcash? cash)
        cash
        (recur (hashcash-iter hash))))))

(defn valid-public-key?
  "check if the public key is trusted"
  [public-key]
  (let [trusted (find-by-keys cyric.db/db :key_bundles {:public (u/unhexify public-key)})]
    (if (empty? trusted)
      false
      true)))

(defn key-receive
  [message]
  (let [message-bytes (u/unhexify (:payload message))
        nonce (u/unhexify (:nonce message))
        public-key (u/unhexify (:public-key message))
        signed-by (u/unhexify (:signed-by message))
        secret-key (lookup-secret-key signed-by)
        decrypted-message (try (bytes->str (b/decrypt public-key secret-key nonce message-bytes))
                     (catch Exception e nil))]
    decrypted-message))

(defn key-send
  "encrypt a message to a given public-key"
  [sender signing-key recipient message]
  (let [message-bytes (str->bytes message)
        nonce (nonce/random-nonce 24)
        box (b/encrypt recipient sender nonce message-bytes)
        cash (hashcash (hashcash-init! (u/hexify signing-key) hashcash-difficulty))]
    {:payload (u/hexify box) :nonce (u/hexify nonce) :public-key (u/hexify recipient) :signed-by (u/hexify signing-key) :cash cash}))

(defn keypair!
  []
  (let [key (b/keypair!)
        public (bs/to-byte-array (:public key))
        secret (bs/to-byte-array (:secret key))]
    {:public public ;public-hex
     :secret secret})) ;secret-hex}))

(defn identity! []
  (let [row (first (query db ["SELECT type FROM key_bundles WHERE type = 'identity'"]))]
    (if (:type row)
      false
      (persist! "key_bundles" (assoc (keypair!) :type "identity" :associated "self" :id (id!) :name "master" :lock 0 :usecount -1)))))

(defn ephemeral-keypair!
  []
  (assoc (keypair!) :type "ephemeral" :usecount 0 :name (cyric.util/id!)))

(defn secret-key!
  []
  {:secret (bs/to-byte-array (sb/new-key!))})

(defn create-ephemeral-keypair
  []
  (let [keypair (keypair!)
        data (assoc keypair :type "ephemeral-key" :id (id!) :usecount 0 :lock 0)]
    (persist! "key_bundles" data)))