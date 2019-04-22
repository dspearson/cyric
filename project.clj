(defproject cyric "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "ISC"}
  :dependencies [[org.clojure/clojure "1.9.0"]
                 [org.clojure/data.json "0.2.6"]
                 [org.clojure/java.jdbc "0.7.8"]
                 [org.clojure/data.codec "0.1.1"]
                 [org.xerial/sqlite-jdbc "3.25.2"]
                 [caesium "0.10.0"]
                 [clj-time "0.15.0"]
                 [byte-streams "0.2.4"]
                 [buddy/buddy-core "1.5.0"]
                 [buddy/buddy-hashers "1.3.0"]
                 [clojure-msgpack "1.2.1"]
                 [ring/ring-core "1.7.1"]
                 [ring/ring-json "0.4.0"]
                 [aleph "0.4.6"]
                 [io.netty/netty-handler-proxy "4.1.33.Final"]
                 [ring/ring-jetty-adapter "1.7.1"]]
  :plugins [[lein-ring "0.12.4"]]
  :ring {:handler cyric.core/app}
  :main ^:skip-aot cyric.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
