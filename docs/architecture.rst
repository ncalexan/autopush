.. _architecture:

============
Architecture
============

Endpoint nodes handle all notification PUT requests, looking up in DynamoDB to
see what Push server the UAID is connected to. The Endpoint nodes then attempt
delivery to the Push server.

Push server's accept websocket connections (this can easily be HTTP/2 for
WebPush), and deliver notifications to connected clients. They check DynamoDB
for missed notifications as necessary.

There will be many more Push servers to handle the connection node, while more
Endpoint nodes can be handled as needed for notification throughput.

Push Characteristics
====================

- When the Push server has sent a client a notification, no further
  notifications will be accepted for delivery (except in one edge case).
  In this state, the Push server will reply to the Endpoint with a 503 to
  indicate it cannot currently deliver the notification. Once the Push
  server has received ack's for all sent notifications, new notifications
  can flow again, and a check of storage will be done if the Push server had
  to reply with a 503. The Endpoint will put the Notification in storage in
  this case.
- (Edge Case) Multiple notifications can be sent at once, if a notification
  comes in during a Storage check, but before it has completed.
- If a connected client is able to accept a notification, then the Endpoint
  will deliver the message to the client completely bypassing Storage. This
  Notification will be referred to as a Direct Notification vs. a Stored
  Notification.
- Provisioned Write Throughput for the Router table determines how many
  connections per second can be accepted across the entire cluster.
- Provisioned Read Throughput for the Router table *and* Provisioned Write
  throughput for the Storage table determine maximum possible notifications
  per second that can be handled. In theory notification throughput can be
  higher than Provisioned Write Throughput on the Storage as connected
  clients will frequently not require using Storage at all. Read's to the
  Router table are still needed for every notification, whether Storage is
  hit or not.
- Provisioned Read Throughput on for the Storage table is an important factor
  in maximum notification throughput, as many slow clients may require frequent
  Storage checks.
- If a client is reconnecting, their Router record will be old. Router records
  have the node_id cleared optimistically by Endpoints when the Endpoint
  discovers it cannot deliver the notification to the Push node on file. If
  the conditional delete fails, it implies that the client has during this
  period managed to connect somewhere again. It's entirely possible that the
  client has reconnected and checked storage before the Endpoint stored the
  Notification, as a result the Endpoint must read the Router table again, and
  attempt to tell the node_id for that client to check storage. Further action
  isn't required, since any more reconnects in this period will have seen the
  stored notification.
