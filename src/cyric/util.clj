(ns cyric.util
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
   [buddy.core.codecs :refer :all]
   [clojure.data.codec.base64 :as b64]
   [buddy.core.nonce :as nonce]
   [clojure.data.json :as json]))

(defn parse-int [s]
  (Integer. (re-find  #"\d+" s)))

(defn uuid!
  []
  (str (java.util.UUID/randomUUID)))

(defn id!
  []
  (bytes->hex (hash/sha256 (uuid!))))

(defn slurp-bytes
  "Slurp the bytes from a slurpable thing"
  [x]
  (with-open [out (java.io.ByteArrayOutputStream.)]
    (io/copy (io/input-stream x) out)
    (.toByteArray out)))

(defn periodically
  "Calls fn every millis. Returns a function that stops the loop."
  [fn millis]
  (let [p (promise)]
    (future
      (while
          (= (deref p millis "timeout") "timeout")
        (fn)))
    #(deliver p "cancel")))
