#!/bin/sh
# Create the folder structure for a Framework
echo "Creating Framework folder structure at ${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}"

# Ensure failure if any simple command fails
set -e

# Create the directory layout
mkdir -p "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/Versions/A/Headers"
mkdir -p "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/Versions/A/Resources"

# Link the "Current" version to "A"
/bin/ln -sfh A "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/Versions/Current"
/bin/ln -sfh Versions/Current/Headers "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/Headers"
/bin/ln -sfh Versions/Current/Resources "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/Resources"
/bin/ln -sfh "Versions/Current/${PRODUCT_NAME}" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}"

# The -a ensures that the headers maintain the source modification date so that we don't constantly
# cause propagating rebuilds of files that import these headers.
echo "Copying public headers from $TARGET_BUILD_DIR/$PUBLIC_HEADERS_FOLDER_PATH/"
/bin/cp -a "${TARGET_BUILD_DIR}/${PUBLIC_HEADERS_FOLDER_PATH}/" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/Versions/A/Headers"

