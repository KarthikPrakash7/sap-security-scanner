service CatalogService {
  entity Products : managed {
    key ID : UUID;
    title : String;
  }
}
