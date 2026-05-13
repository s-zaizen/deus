require "digest"
require "open3"
require "sinatra"
require "sqlite3"

DB = SQLite3::Database.new("/tmp/makina-demo.db")

get "/users" do
  name = params["name"] || ""
  query = "SELECT id, name, role FROM users WHERE name = '#{name}'"
  DB.execute(query).to_json
end

post "/backup" do
  path = params["path"] || "/tmp"
  stdout, = Open3.capture2("tar czf /tmp/backup.tgz #{path}")
  stdout
end

get "/file" do
  name = params["name"] || "readme.txt"
  File.read("/srv/files/#{name}")
end

post "/template" do
  expression = params["expression"] || "1 + 1"
  eval(expression).to_s
end

post "/token" do
  Digest::MD5.hexdigest(params["password"] || "")
end
