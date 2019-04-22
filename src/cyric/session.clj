(ns cyric.session
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
            [cyric.crypto :refer :all]
            [clojure.data.json :as json]))

(defn validate-session
  "mark session as valid, and increase expiry time to 2 weeks"
  [session-id]
  (let [expiry-time (t/plus (t/now) (t/weeks 2))]
    (update! cyric.db/db :sessions {:expiry_time expiry-time} ["session_id = ?" session-id])))

(defn valid-session?
  "check if a session is valid"
  [user-session-id]
  (if (nil? user-session-id)
    false
    (let [result (first (query cyric.db/db ["SELECT session_id, expiry_time FROM sessions WHERE session_id = ?" user-session-id]))
          session-id (:session_id result)
          expiry-time (:expiry_time result)]
      (cond
        (or (nil? session-id)) false
        (t/after? (t/now) (f/parse (f/formatters :date-time) expiry-time)) false
        (= user-session-id session-id) (validate-session session-id)
        :else false))))

(defn session-issue
  "issue a new initial session for the given trusted public-key, with a short expiration"
  [public-key]
  (let [session-id (hex 32)
        expiry-time (t/plus (t/now) (t/minutes 5))]
    (insert! cyric.db/db :sessions {:session_id session-id
                                    :public_key public-key
                                    :expiry_time expiry-time})
    session-id))

(defn session-create
  "create a new session for the given public key"
  [public-key]
  (if (not (and (string? public-key) (valid-public-key? public-key)))
    {:status 404}
    (let [session-id (session-issue public-key)]
      {:status 200 :body (key-send master-secret-key master-public-key (u/unhexify public-key) session-id)})))

(defn session-whoami
  "return the public key associated with the session id"
  [session-id]
  (if (not (string? session-id))
    {:status 404}
    {:status 200 :body {:public-key (:public_key (first (query cyric.db/db ["SELECT public_key FROM sessions WHERE session_id = ?" session-id])))}}))

(defn session-janitor
  "clean timed-out sessions from the database"
  []
  (let [result (delete! cyric.db/db :sessions ["expiry_time < ?" (t/now)])]
    (println (str (t/now)) "Deleted sessions from database:" (first result))))

(defn server-whoami
  []
  {:public-key (u/hexify master-public-key)})