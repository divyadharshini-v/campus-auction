# Campus Auction
Fair, per-item auctions for seniors' leftovers. Node + Express + SQLite, vanilla JS frontend.

    npm install && npm start   # http://localhost:3000

Design: server is the only clock and the only judge of bid validity; bids are append-only and public;
items follow a state machine: active -> unsold | pending_approval -> approved -> sold | failed_pickup; or rejected / cancelled.
