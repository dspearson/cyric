(ns cyric.data
  (:require
   [clojure.java.io :as io]
   [clojure.java.jdbc :refer :all]
   [ring.adapter.jetty :as jetty]
   [crypto.random :refer [hex]]
   [buddy.hashers :as hashers]
   [caesium.crypto.secretbox :as sb]
   [caesium.crypto.box :as b]
   [caesium.byte-bufs :as bu]
   [caesium.util :as u]
   [buddy.core.hash :as hash]
   [clj-time.core :as t]
   [clj-time.format :as f]
   [clj-time.coerce :as c]
   [byte-streams :as bs]
   [msgpack.core :as msg]
   [buddy.core.codecs :refer :all]
   [clojure.data.codec.base64 :as b64]
   [buddy.core.nonce :as nonce]
   [clojure.data.json :as json]))

(def datastore (str (System/getProperty "user.home") "/.cyric"))

(defn init-datastore
  []
  (if (.exists (io/file datastore))
    false
    (io/make-parents (str datastore "/cyric.db"))))

(defn init-blockstore
  []
  (if (.exists (io/file (str datastore "/block")))
    false
    (io/make-parents (str datastore "/block/index"))))

(defn write-manifest
  [hash manifest]
  (let [key (sb/new-key!)
        nonce (nonce/random-nonce 24)
        data (sb/secretbox-easy (str->bytes (json/write-str manifest)) nonce key)
        block (bytes->hex (hash/sha256 data))
        output (with-open [out (io/output-stream (str datastore "/block/" block))]
                           (.write out data))]
    {:size (alength data) :block block :nonce (u/hexify nonce) :key (u/hexify key)}))

(defn encrypt-file
  [file & {:keys [input fh block manifest] :or {input nil fh nil block 0 manifest []}}]
  (let [in (if (nil? input)
             (io/input-stream (io/file file))
             input)
        buf (byte-array (* 500 1000))
        pos (.read in buf)]
    (if (= pos -1)
      (write-manifest fh manifest)
      (let [key (sb/new-key!)
            nonce (nonce/random-nonce 24)
            data (sb/secretbox-easy buf nonce key)
            hash (bytes->hex (hash/sha256 data))
            fh (-> (hash/sha256 (io/input-stream (io/file file)))
                    (bytes->hex))
            output (with-open [out (io/output-stream (str datastore "/block/" hash))]
                     (.write out data))
            manifest (conj manifest {:position block :block hash :nonce (bytes->hex nonce) :key (bytes->hex key)})]
        (recur file {:input in :fh fh :block (+ 1 block) :manifest manifest})))))

(defn decrypt-manifest-block
  [block nonce key]
  (let [data (cyric.util/slurp-bytes (str datastore "/block/" block))]
    (->
     (sb/secretbox-open-easy data (u/unhexify nonce) (u/unhexify key))
     (bytes->str)
     (json/read-str :key-fn keyword))))