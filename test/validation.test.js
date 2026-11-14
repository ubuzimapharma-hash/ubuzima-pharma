import test from "node:test";
import assert from "node:assert/strict";
import {
  validateOrderItems,
  validateNewsArticle,
  validatePatientRegistration,
  validateProduct,
  validateStaffAccount,
  validateStaffInvitation,
  validateVideo
} from "../src/validation.js";

const validProduct = {
  name: "Paracetamol",
  category: "Pain relief",
  description: "Confirmed pharmacy product.",
  price_bif: "2500",
  is_available: "true"
};

test("valid product input is normalized", () => {
  const result = validateProduct(validProduct);
  assert.equal(result.error, undefined);
  assert.deepEqual(result.value, {
    name: "Paracetamol",
    category: "Pain relief",
    description: "Confirmed pharmacy product.",
    priceBif: 2500,
    stockQuantity: 0,
    isAvailable: true,
    generic_name: null,
    active_ingredient: null,
    strength: null,
    dosage_form: null,
    pack_size: null,
    manufacturer: null,
    directions_for_use: null,
    warnings: null,
    storage_instructions: null
  });
});

test("price accepts null and rejects fractions, negatives, and unsafe values", () => {
  assert.equal(validateProduct({ ...validProduct, price_bif: "" }).value.priceBif, null);
  for (const price_bif of ["1.5", "-1", "9007199254740992"]) {
    assert.match(validateProduct({ ...validProduct, price_bif }).error, /Price/);
  }
});

test("product fields are required and length-limited", () => {
  assert.match(validateProduct({ ...validProduct, name: " " }).error, /Name/);
  assert.match(validateProduct({ ...validProduct, category: "x".repeat(81) }).error, /Category/);
  assert.match(validateProduct({ ...validProduct, description: "x".repeat(501) }).error, /Description/);
});

test("availability is restricted to boolean values", () => {
  assert.equal(validateProduct({ ...validProduct, is_available: "false" }).value.isAvailable, false);
  assert.match(validateProduct({ ...validProduct, is_available: "yes" }).error, /Availability/);
});

test("stock must be a non-negative whole number", () => {
  assert.equal(validateProduct({ ...validProduct, stock_quantity: "12" }).value.stockQuantity, 12);
  for (const stock_quantity of ["-1", "1.5", "1000001"]) {
    assert.match(validateProduct({ ...validProduct, stock_quantity }).error, /Stock/);
  }
});

test("optional medicine details are trimmed, retained, and length-limited", () => {
  const result = validateProduct({
    ...validProduct,
    generic_name: "  acetaminophen ",
    active_ingredient: "Acetaminophen",
    strength: "500 mg",
    dosage_form: "Tablet",
    pack_size: "Box of 20",
    manufacturer: "Example Pharma",
    directions_for_use: "Use as directed by a qualified professional.",
    warnings: "Read the package information.",
    storage_instructions: "Store in a dry place."
  });
  assert.equal(result.error, undefined);
  assert.equal(result.value.generic_name, "acetaminophen");
  assert.equal(result.value.directions_for_use, "Use as directed by a qualified professional.");
  assert.equal(result.value.storage_instructions, "Store in a dry place.");
  assert.equal(validateProduct({ ...validProduct, warnings: "x".repeat(2001) }).error, "Warnings must be at most 2000 characters.");
  assert.match(validateProduct({ ...validProduct, strength: 500 }).error, /Strength must be text/);
});

test("patient registration normalizes email and validates required details", () => {
  const result = validatePatientRegistration({
    email: "  Patient@Example.com ",
    full_name: "Patient Example",
    phone: "+257 79 123 456",
    password: "a-secure-passphrase"
  });
  assert.equal(result.error, undefined);
  assert.equal(result.value.email, "patient@example.com");
  assert.match(validatePatientRegistration({ email: "not-an-email" }).error, /email/);
  assert.match(validatePatientRegistration({
    email: "patient@example.com",
    full_name: "Patient",
    phone: "123",
    password: "short"
  }).error, /Password/);
});

test("orders require unique valid products and bounded positive quantities", () => {
  const id = "550e8400-e29b-41d4-a716-446655440000";
  assert.deepEqual(validateOrderItems([{ product_id: id, quantity: 2 }]).value, [{ productId: id, quantity: 2 }]);
  assert.match(validateOrderItems([{ product_id: "bad", quantity: 1 }]).error, /ID/);
  assert.match(validateOrderItems([{ product_id: id, quantity: 0 }]).error, /quantity/);
  assert.match(validateOrderItems([
    { product_id: id, quantity: 1 },
    { product_id: id, quantity: 2 }
  ]).error, /once/);
});

test("staff account roles are restricted", () => {
  const result = validateStaffAccount({
    email: "Pharmacist@Example.com",
    password: "a-secure-passphrase",
    role: "pharmacist"
  });
  assert.equal(result.value.role, "pharmacist");
  assert.equal(result.value.username, "pharmacist@example.com");
  assert.match(validateStaffAccount({
    email: "pharmacist@example.com",
    password: "a-secure-passphrase",
    role: "patient"
  }).error, /Role/);
  assert.match(validateStaffAccount({
    email: "invalid",
    password: "a-secure-passphrase",
    role: "admin"
  }).error, /email/);
});

test("staff invitations normalize email and accept only staff roles", () => {
  const result = validateStaffInvitation({ email: "  Worker@Example.com ", role: "pharmacist" });
  assert.deepEqual(result.value, { email: "worker@example.com", role: "pharmacist" });
  assert.match(validateStaffInvitation({ email: "bad", role: "pharmacist" }).error, /email/);
  assert.match(validateStaffInvitation({ email: "worker@example.com", role: "patient" }).error, /Role/);
});

test("news articles validate required text and allow only HTTPS YouTube or Vimeo URLs", () => {
  const article = {
    title: "Pharmacy update",
    summary: "A short update.",
    body: "Full news content.",
    video_url: "https://youtu.be/example"
  };
  assert.equal(validateNewsArticle(article).value.videoUrl, article.video_url);
  assert.equal(validateNewsArticle({ ...article, video_url: "" }).value.videoUrl, null);
  assert.match(validateNewsArticle({ ...article, title: "" }).error, /Title/);
  assert.match(validateNewsArticle({ ...article, title: "Line one\nLine two" }).error, /control characters/);
  assert.match(validateNewsArticle({ ...article, video_url: "http://youtube.com/watch?v=x" }).error, /HTTPS/);
  assert.match(validateNewsArticle({ ...article, video_url: "https://example.com/video" }).error, /YouTube or Vimeo/);
});

test("news validation sanitizes rich HTML and accepts editorial states", () => {
  const article = validateNewsArticle({
    title: "Pharmacy update",
    summary: "A short update.",
    category: "Ubuzima rusange",
    body: '<h2>Health news</h2><p><strong>Safe</strong><script>alert(1)</script><img src="x" onerror="alert(1)"></p>',
    status: "draft"
  });
  assert.equal(article.error, undefined);
  assert.equal(article.value.category, "Ubuzima rusange");
  assert.equal(article.value.status, "draft");
  assert.match(article.value.body, /<strong>Safe<\/strong>/);
  assert.doesNotMatch(article.value.body, /script|onerror/);
  assert.match(validateNewsArticle({
    title: "Scheduled",
    summary: "A short update.",
    body: "<p>Body</p>",
    status: "scheduled",
    scheduled_at: "2099-01-01T10:00:00.000Z"
  }).value.status, /scheduled/);
  assert.match(validateNewsArticle({ title: "Headline", summary: "Summary", body: "<script>alert(1)</script>" }).error, /News text/);
});

test("video validation separates upload and supported embed sources", () => {
  const upload = validateVideo({
    title: "Medicine guidance",
    description: "How to use medicine safely.",
    category: "Ubuzima",
    source_type: "upload",
    video_url: "/uploads/videos/550e8400-e29b-41d4-a716-446655440000.mp4",
    status: "published"
  });
  assert.equal(upload.error, undefined);
  assert.equal(upload.value.sourceType, "upload");
  assert.match(validateVideo({
    title: "Medicine guidance",
    description: "How to use medicine safely.",
    category: "Ubuzima",
    source_type: "youtube",
    video_url: "https://youtu.be/example",
    status: "draft"
  }).value.status, /draft/);
  assert.match(validateVideo({
    title: "Invalid",
    description: "Invalid host.",
    category: "Ubuzima",
    source_type: "youtube",
    video_url: "https://example.com/video"
  }).error, /HTTPS video URL/);
});
