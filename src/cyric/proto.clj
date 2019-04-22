(ns cyric.proto
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
   [cyric.db :refer :all]
   [cyric.http :refer :all]
   [cyric.crypto :refer :all]
   [buddy.core.codecs :refer :all]
   [clojure.data.codec.base64 :as b64]
   [buddy.core.nonce :as nonce]
   [clojure.data.json :as json]))

(defn message-send
  [params]
  (let [message (:message params)
        recipient (try (u/unhexify (:public-key params))
                       (catch Exception e nil))]
    (if (nil? recipient)
      {:error "could not find recipient"}
      (let [ephemeral-key (get-ephemeral-key)
            sender (:secret ephemeral-key)
            signed-by (:public ephemeral-key)]
        (if ephemeral-key
          (let [cash (hashcash (hashcash-init! (u/hexify signed-by) hashcash-difficulty))]
            (assoc (key-send sender signed-by recipient message) :cash cash))
            {:error "unable to get ephemeral key"})))))

(defn valid-message?
  [message]
  (if (and (= (nth (clojure.string/split (:cash message) #":") 3) (:signed-by message))
           (valid-hashcash? (:cash message)))
    true
    false))

(defn get-node-id
  [node]
  (let [key (:public-key (getj-wrapper node "/server/whoami"))]
    key))