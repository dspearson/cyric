(ns cyric.http
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
            [buddy.core.nonce :as nonce]
            [cyric.crypto :refer :all]
            [clojure.data.json :as json]))

(def http-connection-pool
  (http/connection-pool
   {:dns-options
    {:name-servers '("127.0.0.1:5350")} ;; Tor DNS resolver
    :connection-options
    {:proxy-options
     {:host "127.0.0.1" ;; Tor HTTP CONNECT proxy
      :port 9080
      :tunnel? true}}}))

(defn get-wrapper
  [node endpoint]
  (try
    (->
     @(http/get (str "http://" node endpoint) {:pool http-connection-pool})
     :body
     bs/to-string)
    (catch Exception e nil)))

(defn getj-wrapper
  [node endpoint]
  (try
    (->
     @(http/get (str "http://" node endpoint) {:pool http-connection-pool})
     :body
     bs/to-string
     (json/read-str :key-fn keyword))
    (catch Exception e nil)))

(defn post-wrapper
  [node endpoint body]
  (try
    (->
     @(http/post (str "http://" node endpoint) {:pool http-connection-pool :form-params body :content-type :json})
     :body
     bs/to-string
     (json/read-str :key-fn keyword))
    (catch Exception e nil)))