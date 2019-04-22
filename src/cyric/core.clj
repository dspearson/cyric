(ns cyric.core
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
            [cyric.db :refer :all]
            [cyric.util :refer :all]
            [cyric.session :refer :all]
            [cyric.crypto :refer :all]
            [cyric.proto :refer :all]
            [cyric.http :refer :all]
            [aleph.http :as http]
            [ring.middleware.cookies :refer :all]
            [ring.middleware.content-type :refer :all]
            [ring.middleware.params :refer :all]
            [ring.middleware.keyword-params :refer :all]
            [ring.util.response :refer :all]
            [msgpack.clojure-extensions :refer :all]
            [ring.middleware.json :refer :all]
            [clojure.data.json :as json])
  (:gen-class))

;(defmacro deserialise [& body] `(json/read-str ~@body :key-fn keyword))
;(defmacro serialise [& body] `(json/write-str ~@body))

(def janitor-thread nil)

(defn start-janitor
  []
  (if (nil? janitor-thread)
    (def janitor-thread (periodically (session-janitor) 300000))))

(defn admin-handler
  "main routing handler"
  [request]
  (let [uri (:uri request)
        params (:params request)]
    (case uri
      "/" (response "Cyric Administrative Endpoint")
      "/message/send" (response (message-send params))
      "/key/new" (response (create-ephemeral-keypair))
      "/key/list" (response (list-known-public-keys))
      "/decrypt" (response (key-receive (:params request)))
      {:status 404})))

(def admin-app
  (-> admin-handler
      (wrap-keyword-params)
      (wrap-cookies)
      (wrap-json-response)
      (wrap-json-params)
      (wrap-params)))

(def admin-listener nil)

(defn run-admin-listener
  []
  (if (nil? admin-listener)
    (do
      (def admin-listener (jetty/run-jetty admin-app {:host "localhost" :port 9001 :join? false}))
      "started admin server")
    "admin server already started"))

(defn marco
  [what-to-say]
  what-to-say)

(defn handler
  "main routing handler"
  [request]
  (let [uri (:uri request)
        params (:params request)]
    (case uri
      "/" (response "Cyric")
      "/marco" (response (marco "hello world"))
      "/session/create" (session-create (:public-key params))
      "/session" (if (valid-session? (:session-id params))
                   {:status 200 :body {:ok "session validated"}}
                   {:status 404 :body {:error "invalid session"}})
      "/session/whoami" (response (session-whoami (:session-id params)))
      "/key/put" (add-to-keystore params)
      "/decrypt" (response (key-receive (:params request)))
      "/admin-handler" (response (run-admin-listener))
      "/janitor-handler" (response (start-janitor))
      "/server/whoami" (response (server-whoami))
;     "/publish" (publish request)
      {:status 404})))

(def app
  (-> handler
      (wrap-keyword-params)
      (wrap-cookies)
      (wrap-json-response)
      (wrap-json-params)
      (wrap-params)))

(defn run-main-listener
  []
  (jetty/run-jetty app {:host "localhost" :port 9000 :join? false}))

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (start-janitor)
  (run-admin-listener)
  (jetty/run-jetty app {:host "localhost" :port 9000}))