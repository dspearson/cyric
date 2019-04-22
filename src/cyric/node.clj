(ns cyric.node
  (:require [clojure.java.io :as io]
            [clojure.java.jdbc :refer :all]
            [ring.adapter.jetty :as jetty]
            [crypto.random :refer [hex]]
            [buddy.hashers :as hashers]
            [caesium.crypto.secretbox :as sb]
            [caesium.crypto.box :as b]
            [caesium.byte-bufs :as bu]
            [caesium.util :as u]
            [clj-time.core :as t]
            [clj-time.format :as f]
            [clj-time.coerce :as c]
            [aleph.http :as http]
            [byte-streams :as bs]
            [buddy.core.codecs :refer :all]
            [clojure.data.codec.base64 :as b64]
            [cyric.db :refer :all]
            [cyric.db :refer :all]
            [buddy.core.nonce :as nonce]
            [cyric.crypto :refer :all]
            [clojure.data.json :as json]))

(def nodes (atom {}))

(defn add-to-nodelist
  [node]
  (swap! nodes assoc (keyword (:id node)) (:address node)))

(defn persist-nodelist
  []
  (for [[k v] @nodes]
    (if (node-in-db? (name k))
      (execute! db ["UPDATE nodelist SET address = ? WHERE id = ?" v (name k)])
      (insert! db "nodelist" ["id" "address"] [(name k) v]))))