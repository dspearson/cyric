(ns cyric.db
  (:require [clojure.java.io :as io]
            [clojure.java.jdbc :refer :all]
            [ring.adapter.jetty :as jetty]
            [crypto.random :refer [hex]]
            ;[caesium.crypto.pwhash :as pw]
            [buddy.hashers :as hashers]
            [caesium.crypto.secretbox :as sb]
            [caesium.crypto.box :as b]
            [caesium.byte-bufs :as bu]
            [caesium.util :as u]
            [clj-time.core :as t]
            [clj-time.format :as f]
            [clj-time.coerce :as c]
            [byte-streams :as bs]
            [buddy.core.codecs :refer :all]
            [clojure.data.codec.base64 :as b64]
            [buddy.core.nonce :as nonce]
            [cyric.util :refer :all]
            [cyric.data :refer :all]
            [clojure.data.json :as json]))

(def db
  {:classname   "org.sqlite.JDBC"
   :subprotocol "sqlite"
   :subname     (str cyric.data/datastore "/cyric.db")})

(defn persist!
  [table data]
  (insert! db table data))

(defn persist-multi!
  [table cols data]
  (insert-multi! db table cols data))

(defn list-known-public-keys []
  (let [keys (query db ["select public, type from key_bundles"])]
    (for [key keys]
      {:public-key (u/hexify (:public key)) :type (:type key)})))

(defn get-ephemeral-key []
  (let [ephemeral-key (first (query db ["select public, secret, id from key_bundles where usecount = 0 and type = 'ephemeral-key' and lock != 1 limit 1;"]))
        public (:public ephemeral-key)
        secret (:secret ephemeral-key)
        id (:id ephemeral-key)
        lock-acquired (first (execute! db ["update key_bundles set lock = 1, usecount = 1 where id = ? and type = 'ephemeral-key' and usecount = 0 and lock != 1" id]))]
    (if (= lock-acquired 1)
      {:public public :secret secret}
      false)))

(defn lookup-secret-key
  [public-key]
  (let [secret-key (first (query db ["select secret from key_bundles where (type = 'ephemeral-key' or type = 'identity') and public = ?" public-key]))]
    (:secret secret-key)))

(defn node-in-db?
  [node]
  (let [row (first (query db ["select id from nodelist where id = ?" node]))]
    (if row
      true
      false)))

(defn add-to-keystore
  [params]
  (println params)
  (println (:public params))
  (let [type (:type params)
        key-data {:public (u/unhexify (:public params))}
        id (id!)
        name (:name params)
        type (if (= type "identity") "foreign-identity" "foreign-ephemeral-key")
        data (assoc key-data :type type :id id :usecount -1)]
    (println data)
    (persist! "key_bundles" data)
    {:status 200 :body {:public (:public params)}}))
